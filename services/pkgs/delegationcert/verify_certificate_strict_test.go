package delegationcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// These tests are the adversarial-review probes for FOR-551. Each one
// reproduces a way a malformed or hostile certificate could previously
// reach, or slip past, the verifier.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// rawCert assembles a COSE Sign1 from already-encoded protected bytes and
// an arbitrary unprotected value, so tests can plant non-conforming CBOR.
func rawCert(t *testing.T, protected []byte, unprotected any, sig []byte) []byte {
	t.Helper()
	payload, err := cbor.Marshal(map[int64]any{PayloadLabelSchemaVer: 1})
	require.NoError(t, err)
	b, err := cbor.Marshal([]any{protected, unprotected, payload, sig})
	require.NoError(t, err)
	return b
}

// The envelope must be rejected under EVERY algorithm that does not define
// it — not only plain ES256. The KS256 entry point is a separate function
// and previously had no envelope guard at all, so a -65800 envelope rode
// through it untouched.
func TestKS256RejectsWebAuthnEnvelope(t *testing.T) {
	protected, err := cbor.Marshal(map[int64]any{CoseHeaderAlg: CoseAlgKS256})
	require.NoError(t, err)
	cert := rawCert(t, protected, map[int64]any{
		CoseHeaderWebAuthnEnvelope: []any{
			make([]byte, webAuthnAuthDataMinLen),
			[]byte(`{"type":"webauthn.get","challenge":"x"}`),
		},
	}, make([]byte, 65))

	err = VerifyCertificateSignatureKS256(cert, make([]byte, 20), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected WebAuthn envelope",
		"the envelope guard must run before signature verification")
}

// asBstr accepted a CBOR array-of-small-ints as a byte string. The verify
// paths must not: an attacker could supply structure where bytes are
// required and have it silently coerced.
func TestVerifyRejectsArrayOfIntsAsByteString(t *testing.T) {
	t.Run("protected header", func(t *testing.T) {
		// protected supplied as [163, 1, 58] rather than a bstr.
		cert, err := cbor.Marshal([]any{
			[]any{163, 1, 58},
			map[int64]any{},
			[]byte{0xa0},
			make([]byte, 64),
		})
		require.NoError(t, err)
		err = VerifyCertificateSignature(cert, testRootKey(t), Secp256r1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not bstr")
	})

	t.Run("envelope elements", func(t *testing.T) {
		protected, err := cbor.Marshal(
			map[int64]any{CoseHeaderAlg: CoseAlgES256WebAuthn})
		require.NoError(t, err)
		authAsInts := make([]any, webAuthnAuthDataMinLen)
		for i := range authAsInts {
			authAsInts[i] = 0
		}
		cert := rawCert(t, protected, map[int64]any{
			CoseHeaderWebAuthnEnvelope: []any{
				authAsInts,
				[]any{123, 125},
			},
		}, make([]byte, 64))
		err = VerifyCertificateSignature(cert, testRootKey(t), Secp256r1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not bstr")
	})
}

// Strict CBOR (rules-of-the-road P16). A lax decoder silently resolves
// duplicate keys last-wins, which lets one artifact present two different
// algorithms depending on who parses it.
func TestVerifyRejectsNonCanonicalCBOR(t *testing.T) {
	sig := make([]byte, 64)

	t.Run("duplicate alg key", func(t *testing.T) {
		// {1: -7, 1: -65800} — two entries, same key.
		protected := mustHex(t, "a2"+"0126"+"013a00010107")
		cert := rawCert(t, protected, map[int64]any{}, sig)
		err := VerifyCertificateSignature(cert, testRootKey(t), Secp256r1)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "signature invalid",
			"a duplicate-key header must fail at decode, not verify")
	})

	t.Run("indefinite-length protected map", func(t *testing.T) {
		// bf 01 26 ff  =  {_ 1: -7}
		protected := mustHex(t, "bf"+"0126"+"ff")
		cert := rawCert(t, protected, map[int64]any{}, sig)
		err := VerifyCertificateSignature(cert, testRootKey(t), Secp256r1)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "signature invalid")
	})

	t.Run("non-canonical integer key encoding", func(t *testing.T) {
		// a1 1801 26  =  {1: -7} with key 1 encoded in an 8-bit int.
		protected := mustHex(t, "a1"+"1801"+"26")
		cert := rawCert(t, protected, map[int64]any{}, sig)
		err := VerifyCertificateSignature(cert, testRootKey(t), Secp256r1)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "signature invalid")
	})

	t.Run("duplicate envelope label", func(t *testing.T) {
		protected, err := cbor.Marshal(
			map[int64]any{CoseHeaderAlg: CoseAlgES256WebAuthn})
		require.NoError(t, err)
		// {-65800: [..], -65800: [..]} hand-built with a repeated key.
		env := mustHex(t,
			"a2"+
				"3a00010107"+"82"+"40"+"40"+
				"3a00010107"+"82"+"40"+"40")
		cert, err := cbor.Marshal([]any{
			protected, cbor.RawMessage(env), []byte{0xa0}, make([]byte, 64),
		})
		require.NoError(t, err)
		err = VerifyCertificateSignature(cert, testRootKey(t), Secp256r1)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "signature invalid")
	})
}

// The protocol profile is an UNTAGGED COSE_Sign1. A tag-18 wrapper must be
// rejected rather than silently unwrapped, so one artifact cannot have two
// readings.
func TestVerifyRejectsTaggedCoseSign1(t *testing.T) {
	protected, err := cbor.Marshal(map[int64]any{CoseHeaderAlg: CoseAlgES256})
	require.NoError(t, err)
	inner := rawCert(t, protected, map[int64]any{}, make([]byte, 64))
	tagged, err := cbor.Marshal(cbor.RawTag{
		Number:  18,
		Content: cbor.RawMessage(inner),
	})
	require.NoError(t, err)

	err = VerifyCertificateSignature(tagged, testRootKey(t), Secp256r1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "untagged")
}

// signedWebAuthnCert builds a certificate that would verify, then lets the
// caller perturb one aspect. clientDataTmpl receives the correct challenge.
func signedWebAuthnCert(
	t *testing.T,
	priv *ecdsa.PrivateKey,
	flags byte,
	authDataLen int,
	clientDataTmpl func(challenge string) string,
	envelopeElems func(auth, cd []byte) any,
) []byte {
	t.Helper()
	protected, err := cbor.Marshal(
		map[int64]any{CoseHeaderAlg: CoseAlgES256WebAuthn})
	require.NoError(t, err)
	payload, err := cbor.Marshal(map[int64]any{PayloadLabelSchemaVer: 1})
	require.NoError(t, err)

	sigStructure, err := cbor.Marshal([]any{
		"Signature1", protected, []byte{}, payload,
	})
	require.NoError(t, err)
	digest := sha256.Sum256(sigStructure)
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	clientDataJSON := []byte(clientDataTmpl(challenge))
	authData := make([]byte, authDataLen)
	if authDataLen > 32 {
		authData[32] = flags
	}

	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	assertionDigest := sha256.Sum256(signed)
	r, s, err := ecdsa.Sign(rand.Reader, priv, assertionDigest[:])
	require.NoError(t, err)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	sig = NormalizeES256SignatureLowS(sig)

	cert, err := cbor.Marshal([]any{
		protected,
		map[int64]any{
			CoseHeaderWebAuthnEnvelope: envelopeElems(authData, clientDataJSON),
		},
		payload,
		sig,
	})
	require.NoError(t, err)
	return cert
}

func plainEnvelope(auth, cd []byte) any { return []any{auth, cd} }

func goodClientData(challenge string) string {
	return `{"type":"webauthn.get","challenge":"` + challenge +
		`","origin":"https://example.test"}`
}

// Additional adversarial coverage for the WebAuthn path.
func TestWebAuthnCertificateRejections(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := &priv.PublicKey

	// Control: the helper produces something that verifies, so each
	// rejection below is attributable to its own perturbation.
	t.Run("control verifies", func(t *testing.T) {
		cert := signedWebAuthnCert(t, priv, 0x1d,
			webAuthnAuthDataMinLen, goodClientData, plainEnvelope)
		require.NoError(t,
			VerifyCertificateSignature(cert, pub, Secp256r1))
	})

	// A registration ceremony must never be replayable as a delegation.
	t.Run("webauthn.create ceremony type", func(t *testing.T) {
		cert := signedWebAuthnCert(t, priv, 0x1d, webAuthnAuthDataMinLen,
			func(c string) string {
				return `{"type":"webauthn.create","challenge":"` + c + `"}`
			}, plainEnvelope)
		err := VerifyCertificateSignature(cert, pub, Secp256r1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "webauthn.get")
	})

	// The on-chain algData shape carries index hints; the off-chain
	// envelope must not accept it (ADR-0063 s2).
	t.Run("3-element on-chain algData shape", func(t *testing.T) {
		cert := signedWebAuthnCert(t, priv, 0x1d, webAuthnAuthDataMinLen,
			goodClientData,
			func(auth, cd []byte) any {
				return []any{auth, cd, make([]byte, 16)}
			})
		err := VerifyCertificateSignature(cert, pub, Secp256r1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "2-element")
	})

	// authenticatorData shorter than rpIdHash+flags+signCount.
	t.Run("36-byte authenticatorData", func(t *testing.T) {
		cert := signedWebAuthnCert(t, priv, 0x1d, 36,
			goodClientData, plainEnvelope)
		err := VerifyCertificateSignature(cert, pub, Secp256r1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "at least 37 bytes")
	})

	// The challenge is compared as an unpadded base64url STRING. A padded
	// or standard-alphabet encoding of the same digest must not match.
	t.Run("padded challenge", func(t *testing.T) {
		cert := signedWebAuthnCert(t, priv, 0x1d, webAuthnAuthDataMinLen,
			func(c string) string {
				return `{"type":"webauthn.get","challenge":"` + c + `=="}`
			}, plainEnvelope)
		err := VerifyCertificateSignature(cert, pub, Secp256r1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not bind")
	})

	t.Run("standard-alphabet challenge", func(t *testing.T) {
		cert := signedWebAuthnCert(t, priv, 0x1d, webAuthnAuthDataMinLen,
			func(c string) string {
				std := strings.NewReplacer("-", "+", "_", "/").Replace(c)
				return `{"type":"webauthn.get","challenge":"` + std + `"}`
			}, plainEnvelope)
		err := VerifyCertificateSignature(cert, pub, Secp256r1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not bind")
	})

	// Non-bstr envelope element (array of ints coerced by asBstr).
	t.Run("non-bstr envelope element", func(t *testing.T) {
		cert := signedWebAuthnCert(t, priv, 0x1d, webAuthnAuthDataMinLen,
			goodClientData,
			func(auth, cd []byte) any {
				ints := make([]any, len(auth))
				for i, b := range auth {
					ints[i] = int(b)
				}
				return []any{ints, cd}
			})
		err := VerifyCertificateSignature(cert, pub, Secp256r1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not bstr")
	})
}
