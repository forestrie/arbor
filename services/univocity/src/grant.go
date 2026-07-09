package univocity

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/fxamacker/cbor/v2"
)

// COSE Sign1 unprotected header labels used by Forestrie transparent statements
// (canopy grant/transparent-statement.ts).
const (
	headerReceipt        = 396
	headerIdtimestamp    = -65537
	headerForestrieGrant = -65538
)

// Inner Forestrie-Grant v0 CBOR map labels (canopy grant/codec.ts, keys 1-6).
const (
	grantKeyLogID      = 1
	grantKeyOwnerLogID = 2
	grantKeyFlags      = 3
	grantKeyMaxHeight  = 4
	grantKeyMinGrowth  = 5
	grantKeyGrantData  = 6
)

const idtimestampBytes = 8

var (
	// ErrGrantSignatureInvalid is returned when a grant envelope (or delegation
	// certificate) signature does not verify against the expected key.
	ErrGrantSignatureInvalid = errors.New("signature does not verify against expected key")
	errNotCoseSign1          = errors.New("not a COSE Sign1 (array of 4)")
)

// Grant is a decoded Forestrie-Grant v0 (the inner CBOR payload, keys 1-6).
type Grant struct {
	LogID      logid.UUID
	OwnerLogID logid.UUID
	Flags      []byte
	MaxHeight  uint64
	MinGrowth  uint64
	GrantData  []byte // ES256 public key x||y (64 bytes)
}

// TransparentStatement is a decoded SCITT transparent statement that carries a
// creation grant under the Custodian digest profile.
type TransparentStatement struct {
	Grant       Grant
	Idtimestamp []byte
	Raw         []byte
	cose        coseSign1
}

type coseSign1 struct {
	protected []byte
	payload   []byte
	signature []byte
}

// decodeTransparentStatement mirrors canopy decodeTransparentStatement: the
// COSE Sign1 payload is SHA-256(embedded grant v0 CBOR) and the embedded grant
// lives in unprotected header -65538.
func decodeTransparentStatement(raw []byte) (TransparentStatement, error) {
	if len(raw) == 0 {
		return TransparentStatement{}, errors.New("empty transparent statement")
	}
	cose, unprotected, err := decodeCoseSign1(raw)
	if err != nil {
		return TransparentStatement{}, err
	}
	if len(cose.payload) != 32 {
		return TransparentStatement{}, errors.New(
			"grant Sign1 payload must be a 32-byte digest",
		)
	}
	embedded, ok := unprotected.byteSlice(headerForestrieGrant)
	if !ok || len(embedded) == 0 {
		return TransparentStatement{}, errors.New(
			"grant missing unprotected -65538 (grant v0 cbor)",
		)
	}
	digest := sha256.Sum256(embedded)
	if !bytes.Equal(digest[:], cose.payload) {
		return TransparentStatement{}, errors.New(
			"grant payload digest does not match embedded grant",
		)
	}
	grant, err := decodeGrantPayload(embedded)
	if err != nil {
		return TransparentStatement{}, err
	}
	idts := make([]byte, idtimestampBytes)
	if v, ok := unprotected.byteSlice(headerIdtimestamp); ok && len(v) >= idtimestampBytes {
		copy(idts, v[len(v)-idtimestampBytes:])
	}
	return TransparentStatement{
		Grant:       grant,
		Idtimestamp: idts,
		Raw:         raw,
		cose:        cose,
	}, nil
}

// decodeGrantPayload decodes the inner grant v0 CBOR map (keys 1-6).
func decodeGrantPayload(b []byte) (Grant, error) {
	var top interface{}
	if err := cbor.Unmarshal(b, &top); err != nil {
		return Grant{}, fmt.Errorf("decode grant payload: %w", err)
	}
	m := decodeCBORIntKeyMap(top)
	if m == nil {
		return Grant{}, errors.New("grant payload must be an int-keyed CBOR map")
	}
	logID, ok := m.logidFromWire(grantKeyLogID)
	if !ok {
		return Grant{}, errors.New("grant logId (key 1) must be <=32-byte bstr")
	}
	ownerLogID, ok := m.logidFromWire(grantKeyOwnerLogID)
	if !ok {
		return Grant{}, errors.New("grant ownerLogId (key 2) must be <=32-byte bstr")
	}
	flags, ok := m.byteSlice(grantKeyFlags)
	if !ok {
		return Grant{}, errors.New("grant flags (key 3) must be bstr")
	}
	maxHeight, _ := m.uint(grantKeyMaxHeight)
	minGrowth, _ := m.uint(grantKeyMinGrowth)
	grantData, ok := m.byteSlice(grantKeyGrantData)
	if !ok {
		grantData = nil
	}
	return Grant{
		LogID:      logID,
		OwnerLogID: ownerLogID,
		Flags:      flags,
		MaxHeight:  maxHeight,
		MinGrowth:  minGrowth,
		GrantData:  grantData,
	}, nil
}

// decodeCoseSign1 decodes a COSE Sign1 (tagged or untagged) into its protected,
// payload and signature byte strings plus the unprotected int-keyed header map.
func decodeCoseSign1(raw []byte) (coseSign1, genesisIntMap, error) {
	var top interface{}
	if err := cbor.Unmarshal(raw, &top); err != nil {
		return coseSign1{}, nil, fmt.Errorf("decode COSE Sign1: %w", err)
	}
	if tag, ok := top.(cbor.Tag); ok {
		top = tag.Content
	}
	arr, ok := top.([]interface{})
	if !ok || len(arr) != 4 {
		return coseSign1{}, nil, errNotCoseSign1
	}
	protected, ok := asByteSlice(arr[0])
	if !ok {
		return coseSign1{}, nil, errors.New("COSE protected header is not bstr")
	}
	payload, ok := asByteSlice(arr[2])
	if !ok {
		return coseSign1{}, nil, errors.New("COSE payload is not bstr")
	}
	signature, ok := asByteSlice(arr[3])
	if !ok {
		return coseSign1{}, nil, errors.New("COSE signature is not bstr")
	}
	unprotected := decodeCBORIntKeyMap(arr[1])
	if unprotected == nil {
		unprotected = genesisIntMap{}
	}
	return coseSign1{protected: protected, payload: payload, signature: signature}, unprotected, nil
}

// SetTransparentStatementIdtimestamp rewrites unprotected -65537 on a stored
// COSE Sign1 without touching the protected header, payload, or signature
// (unprotected labels are not covered by the Sign1). Used after sequencing so
// the publisher leaf commitment matches the massif idtimestamp.
func SetTransparentStatementIdtimestamp(raw, idtimestamp []byte) ([]byte, error) {
	if len(idtimestamp) != idtimestampBytes {
		return nil, fmt.Errorf("idtimestamp must be %d bytes", idtimestampBytes)
	}
	if len(raw) == 0 {
		return nil, errors.New("empty transparent statement")
	}
	var top interface{}
	if err := cbor.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("decode COSE Sign1: %w", err)
	}
	var tagNum uint64
	hasTag := false
	if tag, ok := top.(cbor.Tag); ok {
		hasTag = true
		tagNum = tag.Number
		top = tag.Content
	}
	arr, ok := top.([]interface{})
	if !ok || len(arr) != 4 {
		return nil, errNotCoseSign1
	}
	unprotected := decodeCBORIntKeyMap(arr[1])
	if unprotected == nil {
		unprotected = genesisIntMap{}
	}
	idts := make([]byte, idtimestampBytes)
	copy(idts, idtimestamp)
	unprotected[headerIdtimestamp] = idts

	// Rebuild the unprotected map as an int-keyed map for stable CBOR.
	outUnprot := make(map[int]interface{}, len(unprotected))
	for k, v := range unprotected {
		outUnprot[k] = v
	}
	outArr := []interface{}{arr[0], outUnprot, arr[2], arr[3]}
	var content interface{} = outArr
	if hasTag {
		content = cbor.Tag{Number: tagNum, Content: outArr}
	}
	out, err := cbor.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("encode COSE Sign1: %w", err)
	}
	return out, nil
}

func asByteSlice(v interface{}) ([]byte, bool) {
	switch b := v.(type) {
	case []byte:
		return b, true
	case string:
		return []byte(b), true
	case cbor.Tag:
		// cbor-x (canopy) encodes Uint8Array fields as tagged byte strings.
		return asByteSlice(b.Content)
	default:
		return nil, false
	}
}

// logidFromWire decodes a grant log id from <=32-byte padded wire bstr.
func (m genesisIntMap) logidFromWire(label int) (logid.UUID, bool) {
	wire, ok := m.padded32(label)
	if !ok {
		return logid.Zero, false
	}
	return logid.FromPaddedWire32(wire[:]), true
}

// padded32 returns a <=32-byte bstr left-padded to a 32-byte wire log id.
func (m genesisIntMap) padded32(label int) ([32]byte, bool) {
	b, ok := m.byteSlice(label)
	if !ok || len(b) == 0 || len(b) > 32 {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[32-len(b):], b)
	return out, true
}
