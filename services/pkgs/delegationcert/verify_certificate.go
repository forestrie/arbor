package delegationcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	if trustRoot == nil {
		return fmt.Errorf("trust root public key is nil")
	}
	// The caller's asserted curve. Curve has one legal value today, but
	// the assertion is cheap and keeps the caller honest.
	if curve != Secp256r1 {
		return fmt.Errorf(
			"delegation certificates require curve %s, got %s",
			Secp256r1, curve,
		)
	}
	// The load-bearing check: both supported algorithms are P-256. A root
	// on any other curve must be refused here rather than reaching a
	// signature verify that would silently never succeed — or, worse,
	// reaching the WebAuthn flag checks first and reporting the wrong
	// reason.
	if trustRoot.Curve != elliptic.P256() {
		return fmt.Errorf(
			"delegation certificates require a P-256 trust root",
		)
	}

	cfg := certVerifyConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	parts, err := decodeCertificate(certBytes)
	if err != nil {
		return err
	}
	alg, err := algFromParts(parts)
	if err != nil {
		return err
	}

	// Fail closed in BOTH directions, above the switch so it holds for
	// every algorithm including unsupported ones: alg-specific material
	// under an algorithm that defines none is evidence of confusion,
	// never something to ignore (ADR-0063 §5, mirroring the on-chain
	// UnexpectedDelegationAlgData revert and the TypeScript verifier).
	if err := rejectStrayWebAuthnEnvelope(alg, parts); err != nil {
		return err
	}

	sigStructureBytes, err := buildSigStructure(parts)
	if err != nil {
		return err
	}

	switch alg {
	case CoseAlgES256:
		return verifyES256Signature(
			sigStructureBytes, parts.Signature, trustRoot,
		)
	case CoseAlgES256WebAuthn:
		return verifyWebAuthnCertificate(
			parts, sigStructureBytes, trustRoot, cfg,
		)
	default:
		return fmt.Errorf(
			"delegation cert alg %d is not supported by this verifier "+
				"(supported: %d ES256, %d ES256_WEBAUTHN)",
			alg, CoseAlgES256, CoseAlgES256WebAuthn,
		)
	}
}

// rejectStrayWebAuthnEnvelope enforces the mirror fail-closed rule for
// every algorithm that does not define the envelope. It is deliberately
// not inside the ES256 arm: KS256 and unsupported algorithms must reject
// it too, and the KS256 entry point is a separate function.
func rejectStrayWebAuthnEnvelope(alg int64, p *certParts) error {
	if alg == CoseAlgES256WebAuthn {
		return nil
	}
	if hasWebAuthnEnvelope(p) {
		return fmt.Errorf(
			"unexpected WebAuthn envelope at unprotected label %d on an "+
				"alg %d certificate",
			CoseHeaderWebAuthnEnvelope, alg,
		)
	}
	return nil
}

// buildSigStructure encodes the COSE Signature1 structure that both the
// plain and WebAuthn paths bind to.
func buildSigStructure(p *certParts) ([]byte, error) {
	sigStructure := []any{
		"Signature1",
		p.Protected,
		[]byte{},
		p.Payload,
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
//
// This is a verification path, not an informational one — the sealer binds
// its ephemeral key to what this returns — so it decodes the same way
// VerifyCertificateSignature does. A permissive read here could resolve the
// payload differently from the read the signature covered.
func DelegatedKeyFromCertificate(certBytes []byte) (*DelegatedCoseKey, Curve, error) {
	if len(certBytes) == 0 {
		return nil, "", fmt.Errorf("empty certificate")
	}

	var coseArr []any
	if err := strictUnmarshal(certBytes, &coseArr); err != nil {
		return nil, "", fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	if len(coseArr) != 4 {
		return nil, "", fmt.Errorf(
			"unexpected COSE_Sign1 array length: %d", len(coseArr),
		)
	}
	payloadBytes, ok := asBstrStrict(coseArr[2])
	if !ok {
		return nil, "", fmt.Errorf("COSE payload is not bstr")
	}
	payloadMap, err := decodeIntKeyedMapStrict(payloadBytes)
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
