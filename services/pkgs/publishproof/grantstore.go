package publishproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/forestrie/arbor/services/pkgs/logid"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/fxamacker/cbor/v2"
)

// Publish-grant material from the public grant store (plan-2607-02 slice 2).
//
// A stored grant is a SCITT transparent statement: a COSE Sign1 whose payload
// is sha256 of the embedded Forestrie-Grant v0 CBOR (unprotected -65538),
// carrying the sequenced idtimestamp in unprotected -65537 (all zeros for the
// root self-grant, matching the bootstrap convention). Together with the
// grant's leaf position in the owner log — found by scanning the owner
// massif for the grant leaf commitment — this is everything publishCheckpoint
// needs: the PublishGrant tuple, grantIDTimestampBe, and the inclusion proof
// inputs. The decode mirrors the univocity service grant.go
// decodeTransparentStatement.

// Grant transparent-statement wire labels (canopy grant/transparent-statement.ts).
const (
	grantHeaderIdtimestamp = -65537
	grantHeaderEmbedded    = -65538
	grantKeyLogID          = 1
	grantKeyOwnerLogID     = 2
	grantKeyFlags          = 3
	grantKeyMaxHeight      = 4
	grantKeyMinGrowth      = 5
	grantKeyGrantData      = 6
)

// Grant-class request values (univocity constants.sol: high 32 bits of the
// caller-supplied request select the log kind for first checkpoints).
var (
	requestAuthLog = new(big.Int).Lsh(big.NewInt(1), 224)
	requestDataLog = new(big.Int).Lsh(big.NewInt(2), 224)
)

// ErrGrantLeafNotFound indicates the grant's leaf commitment is not present
// in the scanned range of the owner log.
var ErrGrantLeafNotFound = errors.New("grant leaf not found in owner log")

// StoredGrant is the publish-grant material recovered from a stored grant
// object: the calldata-shaped PublishGrant (Request derived from the grant
// class directory) and the sequenced idtimestamp for the leaf commitment.
type StoredGrant struct {
	LogID         logid.UUID
	OwnerLogID    logid.UUID
	IDTimestampBe [8]byte
	Grant         PublishGrant
}

// LeafCommitment returns the grant's authority-log leaf commitment
// (LibLogState: sha256(idTimestampBe || sha256(inner))).
func (g StoredGrant) LeafCommitment() ([32]byte, error) {
	return g.Grant.LeafCommitment(g.IDTimestampBe)
}

// ReadStoredGrant reads logID's creation grant from forest r's public grant
// store, consulting the auth-log then data-log class directories (a subject
// exists in exactly one). Missing grants return an error matching
// massifstorage.ErrDoesNotExist.
func ReadStoredGrant(
	ctx context.Context, store ObjectGetter, r, logID logid.UUID,
) (StoredGrant, error) {
	for _, class := range []struct {
		dir     string
		request *big.Int
	}{
		{"auth-log", requestAuthLog},
		{"data-log", requestDataLog},
	} {
		key := "forests/forest/" + r.String() + "/grants/" + class.dir + "/" + logID.String() + ".cbor"
		body, err := store.Get(ctx, key)
		if errors.Is(err, massifstorage.ErrDoesNotExist) {
			continue
		}
		if err != nil {
			return StoredGrant{}, fmt.Errorf("read grant %s: %w", key, err)
		}
		sg, err := decodeStoredGrant(clampObject(body), class.request)
		if err != nil {
			return StoredGrant{}, fmt.Errorf("grant %s: %w", key, err)
		}
		if sg.LogID != logID {
			return StoredGrant{}, fmt.Errorf("grant %s: subject %s does not match object key", key, sg.LogID)
		}
		return sg, nil
	}
	return StoredGrant{}, fmt.Errorf("no stored grant for %s in forest %s: %w",
		logID, r, massifstorage.ErrDoesNotExist)
}

// decodeStoredGrant decodes a grant transparent statement (COSE Sign1 with
// the grant v0 CBOR embedded at unprotected -65538 and its sha256 digest as
// the payload).
func decodeStoredGrant(raw []byte, request *big.Int) (StoredGrant, error) {
	var top any
	if err := cbor.Unmarshal(raw, &top); err != nil {
		return StoredGrant{}, fmt.Errorf("decode COSE Sign1: %w", err)
	}
	if tag, ok := top.(cbor.Tag); ok {
		top = tag.Content
	}
	arr, ok := top.([]any)
	if !ok || len(arr) != 4 {
		return StoredGrant{}, errors.New("not a COSE Sign1 (array of 4)")
	}
	payload, ok := asBytes(arr[2])
	if !ok || len(payload) != 32 {
		return StoredGrant{}, errors.New("grant Sign1 payload must be a 32-byte digest")
	}
	unprotected := intKeyMap(arr[1])
	if unprotected == nil {
		return StoredGrant{}, errors.New("grant unprotected header must be a CBOR map")
	}
	embedded, ok := asBytes(unprotected[grantHeaderEmbedded])
	if !ok || len(embedded) == 0 {
		return StoredGrant{}, errors.New("grant missing unprotected -65538 (grant v0 cbor)")
	}
	digest := sha256.Sum256(embedded)
	if !bytes.Equal(digest[:], payload) {
		return StoredGrant{}, errors.New("grant payload digest does not match embedded grant")
	}

	var idts [8]byte
	if v, ok := asBytes(unprotected[grantHeaderIdtimestamp]); ok && len(v) >= len(idts) {
		copy(idts[:], v[len(v)-len(idts):])
	}

	var inner any
	if err := cbor.Unmarshal(embedded, &inner); err != nil {
		return StoredGrant{}, fmt.Errorf("decode grant payload: %w", err)
	}
	m := intKeyMap(inner)
	if m == nil {
		return StoredGrant{}, errors.New("grant payload must be an int-keyed CBOR map")
	}
	logWire, ok := paddedWire32(m, grantKeyLogID)
	if !ok {
		return StoredGrant{}, errors.New("grant log-id must be a <=32-byte bstr")
	}
	ownerWire, ok := paddedWire32(m, grantKeyOwnerLogID)
	if !ok {
		return StoredGrant{}, errors.New("grant owner-log-id must be a <=32-byte bstr")
	}
	flags, ok := asBytes(m[grantKeyFlags])
	if !ok || len(flags) == 0 || len(flags) > 8 {
		return StoredGrant{}, errors.New("grant flags must be a 1..8-byte bstr")
	}
	maxHeight, ok := mapUint(m, grantKeyMaxHeight)
	if !ok {
		return StoredGrant{}, errors.New("grant max-height must be an unsigned int")
	}
	minGrowth, ok := mapUint(m, grantKeyMinGrowth)
	if !ok {
		return StoredGrant{}, errors.New("grant min-growth must be an unsigned int")
	}
	grantData, ok := asBytes(m[grantKeyGrantData])
	if !ok {
		return StoredGrant{}, errors.New("grant grant-data must be a bstr")
	}

	return StoredGrant{
		LogID:         logid.FromPaddedWire32(logWire[:]),
		OwnerLogID:    logid.FromPaddedWire32(ownerWire[:]),
		IDTimestampBe: idts,
		Grant: PublishGrant{
			LogId:      logWire,
			Grant:      new(big.Int).SetBytes(flags),
			Request:    new(big.Int).Set(request),
			MaxHeight:  maxHeight,
			MinGrowth:  minGrowth,
			OwnerLogId: ownerWire,
			GrantData:  grantData,
		},
	}, nil
}

// paddedWire32 reads a <=32-byte bstr left-padded to the 32-byte wire form.
func paddedWire32(m map[int]any, label int) ([32]byte, bool) {
	b, ok := asBytes(m[label])
	if !ok || len(b) == 0 || len(b) > 32 {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[32-len(b):], b)
	return out, true
}

// FindGrantLeafIndex locates the grant leaf commitment in the owner log by
// scanning leaf positions in [0, LeafCount(mmrSize)) and returns its mmr node
// index (the InclusionProof index the contract verifies). Content-agnostic:
// non-grant leaves in the authority log are simply skipped. Authority logs
// hold one leaf per grant, so a linear scan is proportionate.
func FindGrantLeafIndex(store NodeGetter, mmrSize uint64, leaf [32]byte) (uint64, error) {
	leaves := mmr.LeafCount(mmrSize)
	for i := uint64(0); i < leaves; i++ {
		nodeIndex := mmr.MMRIndex(i)
		node, err := store.Get(nodeIndex)
		if err != nil {
			return 0, fmt.Errorf("read owner log leaf %d (node %d): %w", i, nodeIndex, err)
		}
		if bytes.Equal(node, leaf[:]) {
			return nodeIndex, nil
		}
	}
	return 0, fmt.Errorf("%w: scanned %d leaves", ErrGrantLeafNotFound, leaves)
}
