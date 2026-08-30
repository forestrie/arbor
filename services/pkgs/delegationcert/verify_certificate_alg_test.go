package delegationcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// certWithAlg builds a syntactically valid COSE Sign1 delegation
// certificate declaring alg, with a well-formed but meaningless signature.
// It exists to exercise algorithm dispatch, not cryptography.
func certWithAlg(t *testing.T, alg int64, sigLen int) []byte {
	t.Helper()
	protected, err := cbor.Marshal(map[int64]any{CoseHeaderAlg: alg})
	require.NoError(t, err)
	payload, err := cbor.Marshal(map[int64]any{PayloadLabelSchemaVer: 1})
	require.NoError(t, err)
	certBytes, err := cbor.Marshal([]any{
		protected,
		map[int64]any{},
		payload,
		make([]byte, sigLen),
	})
	require.NoError(t, err)
	return certBytes
}

func testRootKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &priv.PublicKey
}

// An unsupported algorithm must name itself. Before FOR-551 the declared
// alg was ignored entirely and every certificate was verified as plain
// ES256, so this case surfaced as "COSE signature must be 64 bytes" or
// "delegation cert signature invalid" — bare signature complaints for what
// is actually an unimplemented algorithm.
func TestVerifyCertificateSignatureNamesUnsupportedAlg(t *testing.T) {
	root := testRootKey(t)

	t.Run("ES256_WEBAUTHN", func(t *testing.T) {
		err := VerifyCertificateSignature(
			certWithAlg(t, CoseAlgES256WebAuthn, 64), root, Secp256r1,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "-65800")
		require.Contains(t, err.Error(), "not supported")
		// The old misattributions must not reappear.
		require.NotContains(t, err.Error(), "signature invalid")
		require.NotContains(t, err.Error(), "must be 64 bytes")
	})

	// A DER-shaped assertion signature must still be reported as an
	// unsupported algorithm, not as a length problem: the alg is read
	// before the signature is looked at.
	t.Run("ES256_WEBAUTHN with DER-length signature", func(t *testing.T) {
		err := VerifyCertificateSignature(
			certWithAlg(t, CoseAlgES256WebAuthn, 71), root, Secp256r1,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "-65800")
		require.NotContains(t, err.Error(), "must be 64 bytes")
	})

	t.Run("KS256 on the ES256 path", func(t *testing.T) {
		err := VerifyCertificateSignature(
			certWithAlg(t, CoseAlgKS256, 65), root, Secp256r1,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "-65799")
		require.Contains(t, err.Error(), "not supported")
	})
}

// The curve argument is honoured rather than ignored: it asserts which
// curve the caller believes the trust root is on.
func TestVerifyCertificateSignatureHonoursCurve(t *testing.T) {
	err := VerifyCertificateSignature(
		certWithAlg(t, CoseAlgES256, 64), testRootKey(t), Curve("secp256k1"),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires curve secp256r1")
}

// A malformed ES256 signature still reports as a length problem — the
// existing behaviour for the path that genuinely is ES256.
func TestVerifyCertificateSignatureES256LengthStillReported(t *testing.T) {
	err := VerifyCertificateSignature(
		certWithAlg(t, CoseAlgES256, 71), testRootKey(t), Secp256r1,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "64 bytes")
}
