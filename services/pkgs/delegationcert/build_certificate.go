package delegationcert

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/fxamacker/cbor/v2"
)

// DelegationContentType is the COSE content-type for delegation certificates.
const DelegationContentType = "application/forestrie.delegation+cbor"

// COSE algorithm identifiers.
const (
	CoseAlgES256  = -7  // ECDSA w/ SHA-256 (P-256)
	CoseAlgES256K = -47 // ECDSA w/ SHA-256 (secp256k1)
)

// COSE protected header labels.
const (
	CoseHeaderAlg = 1 // Algorithm
	CoseHeaderCty = 3 // Content type
	CoseHeaderKid = 4 // Key ID
)

// Delegation payload labels per forestrie.delegation profile.
const (
	PayloadLabelLogID        = 1
	PayloadLabelMmrStart     = 3
	PayloadLabelMmrEnd       = 4
	PayloadLabelDelegatedKey = 5
	PayloadLabelConstraints  = 6
	PayloadLabelSchemaVer    = 7
	PayloadLabelIssuedAt     = 8
	PayloadLabelExpiresAt    = 9
	PayloadLabelDelegationID = 10
)

// DelegationInput holds the parameters for building a delegation certificate.
type DelegationInput struct {
	LogID        string            // Optional, 32-char hex log ID
	MmrStart     uint64            // Required if LogID set
	MmrEnd       uint64            // Required if LogID set
	DelegatedKey *DelegatedCoseKey // The delegated EC public key
	Constraints  map[string]any    // Optional constraints map
	DelegationID []byte            // 16 bytes recommended
	IssuedAt     uint64            // Unix timestamp (optional)
	ExpiresAt    uint64            // Unix timestamp (optional)
}

// DelegationToBeSigned holds the components needed to sign a delegation certificate.
type DelegationToBeSigned struct {
	ProtectedBytes     []byte // CBOR-encoded protected header
	PayloadBytes       []byte // CBOR-encoded payload
	SigStructureDigest []byte // SHA-256 of Sig_structure
}

// coseAlgFromCurve returns the COSE algorithm for a curve.
func coseAlgFromCurve(curve Curve) int64 {
	if curve == Secp256r1 {
		return CoseAlgES256
	}
	return CoseAlgES256K
}

// BuildDelegationToBeSigned creates the components for a delegation certificate
// that can be signed externally (e.g., via Custodian).
//
// Returns the protected header bytes, payload bytes, and SHA-256 digest of the
// COSE Sig_structure that should be signed.
func BuildDelegationToBeSigned(curve Curve, kid []byte, input DelegationInput) (*DelegationToBeSigned, error) {
	if input.DelegatedKey == nil {
		return nil, fmt.Errorf("delegated key is required")
	}
	if len(input.DelegationID) == 0 {
		return nil, fmt.Errorf("delegation ID is required")
	}

	alg := coseAlgFromCurve(curve)

	// Build protected header with deterministic ordering.
	// CBOR integer key ordering: positive keys first (ascending), then negative keys (descending by absolute value).
	// For our labels {1, 3, 4}: 1 < 3 < 4.
	protectedMap := map[int64]any{
		CoseHeaderAlg: alg,
		CoseHeaderCty: DelegationContentType,
		CoseHeaderKid: kid,
	}
	protectedBytes, err := encodeDeterministicIntKeyedMap(protectedMap)
	if err != nil {
		return nil, fmt.Errorf("encode protected header: %w", err)
	}

	// Build payload with deterministic ordering.
	payloadMap := make(map[int64]any)
	if input.LogID != "" {
		payloadMap[PayloadLabelLogID] = input.LogID
	}
	if input.LogID != "" {
		payloadMap[PayloadLabelMmrStart] = input.MmrStart
		payloadMap[PayloadLabelMmrEnd] = input.MmrEnd
	}
	payloadMap[PayloadLabelDelegatedKey] = input.DelegatedKey.ToCBORMap()
	if input.Constraints != nil {
		payloadMap[PayloadLabelConstraints] = input.Constraints
	} else {
		payloadMap[PayloadLabelConstraints] = map[string]any{}
	}
	payloadMap[PayloadLabelSchemaVer] = int64(1)
	if input.IssuedAt != 0 {
		payloadMap[PayloadLabelIssuedAt] = input.IssuedAt
	}
	if input.ExpiresAt != 0 {
		payloadMap[PayloadLabelExpiresAt] = input.ExpiresAt
	}
	payloadMap[PayloadLabelDelegationID] = input.DelegationID

	payloadBytes, err := encodeDeterministicIntKeyedMap(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}

	// Build Sig_structure: ["Signature1", protected, external_aad, payload]
	sigStructure := []any{
		"Signature1",
		protectedBytes,
		[]byte{}, // external_aad (empty)
		payloadBytes,
	}
	sigStructureBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("encode sig structure: %w", err)
	}

	digest := sha256.Sum256(sigStructureBytes)

	return &DelegationToBeSigned{
		ProtectedBytes:     protectedBytes,
		PayloadBytes:       payloadBytes,
		SigStructureDigest: digest[:],
	}, nil
}

// AssembleDelegationCert combines the protected header, payload, and signature
// into a complete untagged COSE_Sign1 delegation certificate.
func AssembleDelegationCert(tbs *DelegationToBeSigned, signatureRaw []byte) ([]byte, error) {
	if len(signatureRaw) != 64 {
		return nil, fmt.Errorf("signature must be 64 bytes (IEEE P1363 r||s)")
	}

	// COSE_Sign1 = [protected, unprotected, payload, signature]
	coseSign1 := []any{
		tbs.ProtectedBytes,
		map[any]any{}, // empty unprotected header
		tbs.PayloadBytes,
		signatureRaw,
	}

	return cbor.Marshal(coseSign1)
}

// encodeDeterministicIntKeyedMap encodes a map with int64 keys in deterministic
// CBOR order (keys sorted by CBOR encoding: positive ascending, then negative
// by descending absolute value).
func encodeDeterministicIntKeyedMap(m map[int64]any) ([]byte, error) {
	// CBOR integer encoding order:
	// - Positive integers: 0, 1, 2, ... (major type 0)
	// - Negative integers: -1, -2, -3, ... (major type 1, encoded as -(n+1))
	// Deterministic CBOR sorts by encoded bytes, so:
	// - All positive come before all negative (major type 0 < major type 1)
	// - Within positive: ascending
	// - Within negative: -1, -2, -3, ... (ascending absolute value due to encoding)

	keys := make([]int64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	// Sort: positive keys ascending, then negative keys by ascending absolute value
	sort.Slice(keys, func(i, j int) bool {
		ki, kj := keys[i], keys[j]
		// Positive before negative
		if ki >= 0 && kj < 0 {
			return true
		}
		if ki < 0 && kj >= 0 {
			return false
		}
		// Both positive: ascending
		if ki >= 0 && kj >= 0 {
			return ki < kj
		}
		// Both negative: -1 < -2 < -3 in CBOR encoding
		// Encoded as (major type 1, -(n+1)), so -1 encodes smallest
		return ki > kj
	})

	// Use cbor encoder with deterministic map mode
	encMode, err := cbor.EncOptions{
		Sort: cbor.SortCanonical,
	}.EncMode()
	if err != nil {
		return nil, err
	}

	// Build ordered map for encoding
	orderedMap := make(map[int64]any)
	for _, k := range keys {
		orderedMap[k] = m[k]
	}

	return encMode.Marshal(orderedMap)
}
