package delegationcert

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// WebAuthn authenticatorData flag bits (WebAuthn L2 §6.1).
const (
	webAuthnFlagUP = 0x01 // User present
	webAuthnFlagUV = 0x04 // User verified
	webAuthnFlagBE = 0x08 // Backup eligible
	webAuthnFlagBS = 0x10 // Backed up
)

// webAuthnAuthDataMinLen is rpIdHash(32) + flags(1) + signCount(4).
const webAuthnAuthDataMinLen = 37

// certVerifyConfig carries optional certificate verification policy. The
// zero value is the safe default.
type certVerifyConfig struct {
	requireUserVerification bool
}

// CertificateVerifyOption adjusts certificate verification policy.
type CertificateVerifyOption func(*certVerifyConfig)

// WithRequireUserVerification requires the WebAuthn UV (user verified)
// flag on a CoseAlgES256WebAuthn certificate's assertion.
//
// It defaults to FALSE, deliberately. User verification is per-log policy
// declared by the grant flag GF_REQUIRES_USER_VERIFICATION (devdocs
// ADR-0062), and a bare certificate verify has no grant in evidence — the
// sealer verifies a lease, not a grant. devdocs ADR-0063 §4 records that
// asymmetry as accepted: the on-chain verifier backstops UV at publish,
// where the grant IS in evidence. A caller that does hold the grant should
// pass the flag through rather than relying on this default.
//
// User presence (UP) is always required and is not optional.
func WithRequireUserVerification(require bool) CertificateVerifyOption {
	return func(c *certVerifyConfig) { c.requireUserVerification = require }
}

// clientData is the subset of clientDataJSON this verifier reads.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
}

// verifyWebAuthnCertificate verifies a CoseAlgES256WebAuthn delegation
// certificate (devdocs ADR-0063).
//
// The assertion material rides in the UNPROTECTED header and is therefore
// not covered by the signature. It is trustworthy only because the
// challenge re-derives the tie to this certificate:
//
//	clientDataJSON.challenge == base64url(SHA-256(Sig_structure))
//
// Without that equality the assertion proves key possession and says
// nothing about this certificate.
func verifyWebAuthnCertificate(
	parts *certParts,
	sigStructureBytes []byte,
	trustRoot *ecdsa.PublicKey,
	cfg certVerifyConfig,
) error {
	signature := parts.Signature
	authData, clientDataJSON, err := webAuthnEnvelopeFromParts(parts)
	if err != nil {
		return err
	}

	if err := checkAuthenticatorFlags(authData, cfg); err != nil {
		return err
	}

	var cd clientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return fmt.Errorf("decode clientDataJSON: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return fmt.Errorf(
			"clientDataJSON type %q is not webauthn.get", cd.Type,
		)
	}

	// Challenge binding: this is the security argument.
	digest := sha256.Sum256(sigStructureBytes)
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	if cd.Challenge != want {
		return fmt.Errorf(
			"WebAuthn challenge does not bind this certificate",
		)
	}

	if len(signature) != 64 {
		return fmt.Errorf(
			"WebAuthn assertion signature must be 64 bytes r||s, got %d "+
				"(a DER-encoded assertion must be converted first)",
			len(signature),
		)
	}
	if !isLowS(signature) {
		return fmt.Errorf("WebAuthn assertion signature is not low-s")
	}

	// The authenticator signed authenticatorData || SHA-256(clientDataJSON),
	// never the Sig_structure digest directly.
	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)
	assertionDigest := sha256.Sum256(signed)

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(trustRoot, assertionDigest[:], r, s) {
		return fmt.Errorf("delegation cert signature invalid")
	}
	return nil
}

// checkAuthenticatorFlags enforces the ADR-0063 §4 policy. User presence
// is always required; user verification is opt-in (see
// WithRequireUserVerification). A credential marked backed-up without
// being backup-eligible is incoherent and rejected.
func checkAuthenticatorFlags(authData []byte, cfg certVerifyConfig) error {
	if len(authData) < webAuthnAuthDataMinLen {
		return fmt.Errorf(
			"authenticatorData must be at least %d bytes, got %d",
			webAuthnAuthDataMinLen, len(authData),
		)
	}
	flags := authData[32]
	if flags&webAuthnFlagUP == 0 {
		return fmt.Errorf("WebAuthn user presence flag not set")
	}
	if cfg.requireUserVerification && flags&webAuthnFlagUV == 0 {
		return fmt.Errorf("WebAuthn user verification required but not set")
	}
	if flags&webAuthnFlagBS != 0 && flags&webAuthnFlagBE == 0 {
		return fmt.Errorf(
			"WebAuthn credential is backed up but not backup eligible",
		)
	}
	return nil
}

// webAuthnEnvelopeFromParts reads the 2-element assertion envelope from
// the certificate's unprotected header at CoseHeaderWebAuthnEnvelope.
//
// Unlike the on-chain algData, the off-chain envelope carries NO
// challengeIndex/typeIndex hint element: those exist on-chain only to
// avoid scanning JSON at Solidity gas prices, and carrying them here would
// create a verify-or-ignore obligation for no gain (ADR-0063 s2). A
// 3-element on-chain-shaped algData is therefore rejected here.
//
// Elements must be genuine CBOR byte strings: asBstrStrict, not asBstr.
// The permissive helper coerces an array of small integers into bytes,
// which would let a hostile encoder supply structure where bytes are
// required.
func webAuthnEnvelopeFromParts(p *certParts) (authData, clientDataJSON []byte, err error) {
	raw, ok := p.Unprotected[CoseHeaderWebAuthnEnvelope]
	if !ok {
		return nil, nil, fmt.Errorf(
			"certificate declares alg %d but carries no WebAuthn "+
				"assertion envelope at unprotected label %d",
			CoseAlgES256WebAuthn, CoseHeaderWebAuthnEnvelope,
		)
	}
	arr, ok := raw.([]any)
	if !ok || len(arr) != 2 {
		return nil, nil, fmt.Errorf(
			"WebAuthn envelope must be a 2-element array " +
				"[authenticatorData, clientDataJSON]",
		)
	}
	authData, ok = asBstrStrict(arr[0])
	if !ok {
		return nil, nil, fmt.Errorf("authenticatorData is not bstr")
	}
	clientDataJSON, ok = asBstrStrict(arr[1])
	if !ok {
		return nil, nil, fmt.Errorf("clientDataJSON is not bstr")
	}
	return authData, clientDataJSON, nil
}
