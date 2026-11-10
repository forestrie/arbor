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
	"github.com/forestrie/go-univocity/grant"
	"github.com/fxamacker/cbor/v2"
)

// Publish-grant material from the public grant store (plan-2607-02 slice 2).
//
// A stored grant is a SCITT transparent statement: a COSE Sign1 whose payload
// is sha256 of the embedded Forestrie-Grant v0 CBOR (unprotected -65538).
// Nothing records where the grant was sequenced (devdocs ADR-0075 decision
// 10): its leaf in the owner log, found by scanning the owner's leaves for
// the grant's commitment (GrantLeafIndex), supplies the idtimestamp and the
// inclusion proof inputs. Together with the PublishGrant tuple decoded here,
// that is everything publishCheckpoint needs. The decode mirrors the
// univocity service grant.go decodeTransparentStatement.

// Grant transparent-statement wire labels (canopy grant/transparent-statement.ts).
const (
	grantHeaderEmbedded = -65538
	grantKeyLogID       = 1
	grantKeyOwnerLogID  = 2
	grantKeyFlags       = 3
	grantKeyMaxHeight   = 4
	grantKeyMinGrowth   = 5
	grantKeyGrantData   = 6
)

// grantKeyObsoleteSigner and grantKeyObsoleteKind are the retired grant keys
// 7 (signer) and 8 (kind). The grant wire format is keys 0-6 only; grantData
// is the sole signer binding (owner ruling 2026-09-22, devdocs plan-2609-09
// decision P2; matches go-univocity's ErrGrantObsoleteKey,
// https://github.com/forestrie/go-univocity/pull/2). decodeStoredGrant
// rejects either key on sight instead of ignoring it.
const (
	grantKeyObsoleteSigner = 7
	grantKeyObsoleteKind   = 8
)

// ErrGrantObsoleteKey is returned by decodeStoredGrant when the grant
// payload map carries CBOR key 7 (the retired signer field) or key 8 (the
// retired kind field). Callers can use errors.Is(err, ErrGrantObsoleteKey).
var ErrGrantObsoleteKey = errors.New("grant carries an obsolete CBOR key (7 signer or 8 kind)")

// Grant-class request values (univocity constants.sol: high 32 bits of the
// caller-supplied request select the log kind for first checkpoints).
var (
	requestAuthLog = new(big.Int).Lsh(big.NewInt(1), 224)
	requestDataLog = new(big.Int).Lsh(big.NewInt(2), 224)
)

// StoredGrant is the publish-grant material recovered from a stored grant
// object: the calldata-shaped PublishGrant, with Request derived from the
// grant class directory.
type StoredGrant struct {
	LogID      logid.UUID
	OwnerLogID logid.UUID
	Grant      PublishGrant
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

	var inner any
	if err := cbor.Unmarshal(embedded, &inner); err != nil {
		return StoredGrant{}, fmt.Errorf("decode grant payload: %w", err)
	}
	m := intKeyMap(inner)
	if m == nil {
		return StoredGrant{}, errors.New("grant payload must be an int-keyed CBOR map")
	}
	if _, ok := m[grantKeyObsoleteSigner]; ok {
		return StoredGrant{}, fmt.Errorf("grant payload carries retired key %d (signer): %w", grantKeyObsoleteSigner, ErrGrantObsoleteKey)
	}
	if _, ok := m[grantKeyObsoleteKind]; ok {
		return StoredGrant{}, fmt.Errorf("grant payload carries retired key %d (kind): %w", grantKeyObsoleteKind, ErrGrantObsoleteKey)
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
		LogID:      logid.FromPaddedWire32(logWire[:]),
		OwnerLogID: logid.FromPaddedWire32(ownerWire[:]),
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

// ContentHash returns the grant's sequencing content hash (the grant
// InnerHash): the value ranger commits under the grant's idtimestamp, so the
// mmr leaf is sha256(idtimestampBe || ContentHash).
func (g StoredGrant) ContentHash() ([32]byte, error) {
	if g.Grant.Grant == nil || g.Grant.Grant.Sign() < 0 || g.Grant.Grant.BitLen() > 64 {
		return [32]byte{}, errors.New("grant flags must be a non-negative value fitting 8 bytes")
	}
	var flags [8]byte
	g.Grant.Grant.FillBytes(flags[:])
	return grant.InnerHash(
		g.Grant.LogId[:],
		flags[:],
		g.Grant.MaxHeight,
		g.Grant.MinGrowth,
		g.Grant.OwnerLogId[:],
		g.Grant.GrantData,
	), nil
}
