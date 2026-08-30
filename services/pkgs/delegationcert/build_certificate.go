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
	CoseAlgES256 = -7 // ECDSA w/ SHA-256 (P-256)
	// CoseAlgKS256 is secp256k1 + Keccak-256 + Ethereum address / ERC-1271.
	CoseAlgKS256 = -65799
	// CoseAlgES256WebAuthn is ALG_ES256_WEBAUTHN (univocity ADR-0008,
	// devdocs ADR-0063): a P-256 key whose signature is a WebAuthn
	// assertion rather than a plain COSE signature.
	//
	// It is a SIGNATURE algorithm, not a key type. The key is an ordinary
	// P-256 point, so a trust root is never advertised with this alg —
	// grantDataIdentity infers ES256 from a 64-byte key and that is
	// correct. Only the certificate's signature envelope is WebAuthn.
	CoseAlgES256WebAuthn = -65800
)

// COSE protected header labels.
const (
	CoseHeaderAlg = 1 // Algorithm
	CoseHeaderCty = 3 // Content type
	CoseHeaderKid = 4 // Key ID
)

// CoseHeaderWebAuthnEnvelope is the UNPROTECTED header label carrying the
// 2-element WebAuthn assertion envelope [authenticatorData, clientDataJSON]
// on a CoseAlgES256WebAuthn certificate (devdocs ADR-0063 §2).
//
// It deliberately shares the numeric value of CoseAlgES256WebAuthn: the
// original design let the alg id double as the header label. The two live
// in different COSE registries and never occupy the same parse position —
// the alg is a VALUE under protected label 1, this is a KEY in the
// unprotected map — so it is not a wire ambiguity. It is still a recorded
// bug (devdocs protocol/label-registry.md §4, where the label is being
// separated as TBD1), which is why it is declared here as its own named
// constant rather than reusing CoseAlgES256WebAuthn at the use site.
const CoseHeaderWebAuthnEnvelope = -65800

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
	if curve != Secp256r1 {
		panic("unsupported delegation curve")
	}
	return CoseAlgES256
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

	// Use cbor encoder with RFC 8949 §4.2 core deterministic map ordering
	// (bytewise lexicographic on encoded keys) — the COSE/SCITT canonical
	// profile, matching the rest of arbor (go-merklelog, go-datatrails-common)
	// and the TS @canopy/encoding writer. NB: fxamacker's SortCanonical is the
	// legacy RFC 7049 *length-first* ordering, which diverges from §4.2 once a
	// multi-byte key (>=24) appears; the current delegation labels are all
	// single-byte so this switch is byte-identical for existing certs.
	encMode, err := cbor.EncOptions{
		Sort: cbor.SortCoreDeterministic,
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
