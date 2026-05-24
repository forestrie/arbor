package delegationcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// VerifyCertificateSignature verifies the COSE Sign1 signature on a delegation
// certificate against the expected trust-root public key.
func VerifyCertificateSignature(certBytes []byte, trustRoot *ecdsa.PublicKey, curve Curve) error {
	if len(certBytes) == 0 {
		return fmt.Errorf("empty certificate")
	}
	if trustRoot == nil {
		return fmt.Errorf("trust root public key is nil")
	}

	var coseArr []any
	if err := cbor.Unmarshal(certBytes, &coseArr); err != nil {
		return fmt.Errorf("decode COSE Sign1: %w", err)
	}
	if len(coseArr) != 4 {
		return fmt.Errorf("unexpected COSE Sign1 array length: %d", len(coseArr))
	}
	protectedBytes, ok := asBstr(coseArr[0])
	if !ok {
		return fmt.Errorf("COSE protected header is not bstr")
	}
	payloadBytes, ok := asBstr(coseArr[2])
	if !ok {
		return fmt.Errorf("COSE payload is not bstr")
	}
	signature, ok := asBstr(coseArr[3])
	if !ok || len(signature) != 64 {
		return fmt.Errorf("COSE signature must be 64 bytes")
	}

	sigStructure := []any{
		"Signature1",
		protectedBytes,
		[]byte{},
		payloadBytes,
	}
	sigStructureBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("encode sig structure: %w", err)
	}
	digest := sha256.Sum256(sigStructureBytes)

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(trustRoot, digest[:], r, s) {
		return fmt.Errorf("delegation cert signature invalid")
	}
	return nil
}

// DelegatedKeyFromCertificate extracts the delegated EC public key from a
// delegation certificate payload (label 5).
func DelegatedKeyFromCertificate(certBytes []byte) (*DelegatedCoseKey, Curve, error) {
	if len(certBytes) == 0 {
		return nil, "", fmt.Errorf("empty certificate")
	}

	var coseArr []any
	if err := cbor.Unmarshal(certBytes, &coseArr); err != nil {
		return nil, "", fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	payloadBytes, ok := asBstr(coseArr[2])
	if !ok {
		return nil, "", fmt.Errorf("COSE payload is not bstr")
	}
	payloadMap, err := decodeIntKeyedMap(payloadBytes)
	if err != nil {
		return nil, "", fmt.Errorf("decode payload: %w", err)
	}
	rawKey, ok := payloadMap[PayloadLabelDelegatedKey]
	if !ok {
		return nil, "", fmt.Errorf("payload missing delegated key")
	}
	m, ok := normalizeAnyIntKeyedMap(rawKey)
	if !ok {
		return nil, "", fmt.Errorf("delegated key is not a map")
	}
	return delegatedCoseKeyFromMap(m)
}

// DelegatedKeyMatches compares a delegated COSE key to an ephemeral public key.
func DelegatedKeyMatches(delegated *DelegatedCoseKey, pub *ecdsa.PublicKey) bool {
	if delegated == nil || pub == nil || pub.X == nil || pub.Y == nil {
		return false
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return bytes.Equal(delegated.X, x) && bytes.Equal(delegated.Y, y)
}
