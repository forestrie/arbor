package delegationcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// VerifyCertificateSignature verifies the COSE Sign1 signature on a
// delegation certificate against the expected trust-root public key.
//
// The certificate's DECLARED algorithm (protected header label 1) selects
// the verification path, and an algorithm this verifier does not implement
// fails with an error naming it. Before FOR-551 this function ignored the
// declared alg entirely and verified everything as plain ES256, so a
// WebAuthn-enveloped certificate failed as a bare signature or length
// complaint rather than as an unimplemented algorithm.
func VerifyCertificateSignature(
	certBytes []byte,
	trustRoot *ecdsa.PublicKey,
	curve Curve,
	opts ...CertificateVerifyOption,
) error {
	if len(certBytes) == 0 {
		return fmt.Errorf("empty certificate")
	}
	if trustRoot == nil {
		return fmt.Errorf("trust root public key is nil")
	}

	cfg := certVerifyConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	protectedBytes, payloadBytes, signature, err :=
		decodeCoseSign1Parts(certBytes)
	if err != nil {
		return err
	}
	alg, err := algFromProtectedHeader(protectedBytes)
	if err != nil {
		return err
	}
	if err := checkAlgCurve(alg, curve); err != nil {
		return err
	}

	sigStructureBytes, err := buildSigStructure(protectedBytes, payloadBytes)
	if err != nil {
		return err
	}

	switch alg {
	case CoseAlgES256:
		// Fail closed in the other direction too: alg-specific material
		// under an algorithm that defines none is evidence of confusion,
		// never something to ignore (ADR-0063 §5).
		if certHasWebAuthnEnvelope(certBytes) {
			return fmt.Errorf(
				"unexpected WebAuthn envelope at unprotected label %d on "+
					"an alg %d (ES256) certificate",
				CoseHeaderWebAuthnEnvelope, CoseAlgES256,
			)
		}
		return verifyES256Signature(sigStructureBytes, signature, trustRoot)
	case CoseAlgES256WebAuthn:
		return verifyWebAuthnCertificate(
			certBytes, sigStructureBytes, signature, trustRoot, cfg,
		)
	default:
		return fmt.Errorf(
			"delegation cert alg %d is not supported by this verifier "+
				"(supported: %d ES256, %d ES256_WEBAUTHN)",
			alg, CoseAlgES256, CoseAlgES256WebAuthn,
		)
	}
}

// checkAlgCurve honours the caller's asserted curve. The caller is stating
// which curve it believes the trust root is on; a declared alg that cannot
// be verified on that curve is a mismatch, not something to ignore.
func checkAlgCurve(alg int64, curve Curve) error {
	switch alg {
	case CoseAlgES256, CoseAlgES256WebAuthn:
		if curve != Secp256r1 {
			return fmt.Errorf(
				"delegation cert alg %d requires curve %s, got %s",
				alg, Secp256r1, curve,
			)
		}
		return nil
	default:
		// Unsupported algs are reported by the caller's switch, which
		// names the alg; do not pre-empt that with a curve error.
		return nil
	}
}

// buildSigStructure encodes the COSE Signature1 structure that both the
// plain and WebAuthn paths bind to.
func buildSigStructure(protectedBytes, payloadBytes []byte) ([]byte, error) {
	sigStructure := []any{
		"Signature1",
		protectedBytes,
		[]byte{},
		payloadBytes,
	}
	sigStructureBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("encode sig structure: %w", err)
	}
	return sigStructureBytes, nil
}

// verifyES256Signature is the plain COSE path: the signer signed
// SHA-256(Sig_structure) directly.
func verifyES256Signature(
	sigStructureBytes, signature []byte,
	trustRoot *ecdsa.PublicKey,
) error {
	if len(signature) != 64 {
		return fmt.Errorf(
			"ES256 COSE signature must be 64 bytes, got %d", len(signature),
		)
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
