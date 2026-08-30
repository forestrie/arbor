package publishproof

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// goldenRootKey rebuilds the passkey root public key from the capture.
func goldenRootKey(t *testing.T, g webauthnGolden) *ecdsa.PublicKey {
	t.Helper()
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(goldenHex(t, g.RootX)),
		Y:     new(big.Int).SetBytes(goldenHex(t, g.RootY)),
	}
}

// TestWebauthnGoldenCertificateVerifies is the FOR-551 acceptance test: a
// real-authenticator, WebAuthn-enveloped delegation certificate verifies
// against the passkey root through the same entry point the sealer calls.
//
// The fixture is byte-identical across univocity, canopy and arbor, so
// this asserts the Go verifier agrees with the Solidity and TypeScript
// ones about one genuine gesture.
func TestWebauthnGoldenCertificateVerifies(t *testing.T) {
	g := loadWebauthnGolden(t)
	require.NotEmpty(t, g.Certificate.CoseSign1,
		"fixture is missing the certificate section")

	certBytes := goldenHex(t, g.Certificate.CoseSign1)
	root := goldenRootKey(t, g)

	require.NoError(t, delegationcert.VerifyCertificateSignature(
		certBytes, root, delegationcert.Secp256r1,
	))
}

// The certificate declares the WebAuthn alg and carries the 2-element
// envelope — not the on-chain 3-element algData shape.
func TestWebauthnGoldenCertificateShape(t *testing.T) {
	g := loadWebauthnGolden(t)
	certBytes := goldenHex(t, g.Certificate.CoseSign1)

	var coseArr []any
	require.NoError(t, cbor.Unmarshal(certBytes, &coseArr))
	require.Len(t, coseArr, 4)

	protectedBytes, ok := coseArr[0].([]byte)
	require.True(t, ok)
	var protectedMap map[any]any
	require.NoError(t, cbor.Unmarshal(protectedBytes, &protectedMap))
	require.EqualValues(t, delegationcert.CoseAlgES256WebAuthn,
		protectedMap[uint64(delegationcert.CoseHeaderAlg)])

	unprotected, ok := coseArr[1].(map[any]any)
	require.True(t, ok)
	var envelope []any
	for k, v := range unprotected {
		if ki, isInt := k.(int64); isInt &&
			ki == delegationcert.CoseHeaderWebAuthnEnvelope {
			envelope, _ = v.([]any)
		}
	}
	require.Len(t, envelope, 2,
		"off-chain envelope is [authenticatorData, clientDataJSON] with "+
			"no index hints (ADR-0063 §2)")
}

// The challenge binding is the security argument, so assert it against the
// captured values rather than trusting that verification passed.
func TestWebauthnGoldenCertificateChallengeBinding(t *testing.T) {
	g := loadWebauthnGolden(t)
	certBytes := goldenHex(t, g.Certificate.CoseSign1)

	var coseArr []any
	require.NoError(t, cbor.Unmarshal(certBytes, &coseArr))
	protectedBytes := coseArr[0].([]byte)
	payloadBytes := coseArr[2].([]byte)

	sigStructureBytes, err := cbor.Marshal([]any{
		"Signature1", protectedBytes, []byte{}, payloadBytes,
	})
	require.NoError(t, err)

	// The rebuilt Sig_structure must match the captured bytes exactly.
	require.Equal(t, goldenHex(t, g.Certificate.SigStructure),
		sigStructureBytes)

	digest := sha256.Sum256(sigStructureBytes)
	require.Equal(t, g.Certificate.ChallengeB64u,
		base64.RawURLEncoding.EncodeToString(digest[:]))
}

// Mutation negatives. Each alters exactly one thing and must fail; none
// may fall back to a plain ES256 verify.
func TestWebauthnGoldenCertificateMutations(t *testing.T) {
	g := loadWebauthnGolden(t)
	root := goldenRootKey(t, g)
	authData := goldenHex(t, g.Certificate.AuthenticatorData)
	clientDataJSON := goldenHex(t, g.Certificate.ClientDataJSON)
	signature := goldenHex(t, g.Certificate.Signature)

	var coseArr []any
	require.NoError(t,
		cbor.Unmarshal(goldenHex(t, g.Certificate.CoseSign1), &coseArr))
	protectedBytes := coseArr[0].([]byte)
	payloadBytes := coseArr[2].([]byte)

	// rebuild reassembles the certificate from parts so each mutation is
	// isolated to one field.
	rebuild := func(t *testing.T, protected []byte, env []any, sig []byte) []byte {
		t.Helper()
		unprotected := map[int64]any{}
		if env != nil {
			unprotected[delegationcert.CoseHeaderWebAuthnEnvelope] = env
		}
		b, err := cbor.Marshal([]any{
			protected, unprotected, payloadBytes, sig,
		})
		require.NoError(t, err)
		return b
	}
	envelope := func(ad, cd []byte) []any { return []any{ad, cd} }

	// Control: the rebuilt certificate still verifies, so a failure below
	// is attributable to the mutation and not to reassembly.
	t.Run("control", func(t *testing.T) {
		require.NoError(t, delegationcert.VerifyCertificateSignature(
			rebuild(t, protectedBytes, envelope(authData, clientDataJSON),
				signature),
			root, delegationcert.Secp256r1,
		))
	})

	t.Run("missing envelope", func(t *testing.T) {
		err := delegationcert.VerifyCertificateSignature(
			rebuild(t, protectedBytes, nil, signature),
			root, delegationcert.Secp256r1,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "envelope")
		require.NotContains(t, err.Error(), "signature invalid")
	})

	t.Run("mutated challenge", func(t *testing.T) {
		// Locate the challenge value precisely rather than scanning for
		// an arbitrary character: a scan can land anywhere in the JSON,
		// which would make this assert nothing about challenge binding.
		bad := append([]byte(nil), clientDataJSON...)
		at := bytes.Index(bad, []byte(g.Certificate.ChallengeB64u))
		require.GreaterOrEqual(t, at, 0,
			"challenge must appear verbatim in clientDataJSON")
		if bad[at] == 'A' {
			bad[at] = 'B'
		} else {
			bad[at] = 'A'
		}

		err := delegationcert.VerifyCertificateSignature(
			rebuild(t, protectedBytes, envelope(authData, bad), signature),
			root, delegationcert.Secp256r1,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not bind",
			"must fail challenge binding, not merely the signature")
	})

	t.Run("user presence cleared", func(t *testing.T) {
		bad := append([]byte(nil), authData...)
		bad[32] &^= 0x01
		err := delegationcert.VerifyCertificateSignature(
			rebuild(t, protectedBytes, envelope(bad, clientDataJSON),
				signature),
			root, delegationcert.Secp256r1,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "user presence")
	})

	t.Run("backed up without backup eligible", func(t *testing.T) {
		bad := append([]byte(nil), authData...)
		bad[32] |= 0x10  // BS
		bad[32] &^= 0x08 // clear BE
		err := delegationcert.VerifyCertificateSignature(
			rebuild(t, protectedBytes, envelope(bad, clientDataJSON),
				signature),
			root, delegationcert.Secp256r1,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "backup eligible")
	})

	t.Run("high-s signature twin", func(t *testing.T) {
		n := elliptic.P256().Params().N
		s := new(big.Int).SetBytes(signature[32:])
		high := new(big.Int).Sub(n, s)
		bad := make([]byte, 64)
		copy(bad, signature[:32])
		high.FillBytes(bad[32:])
		err := delegationcert.VerifyCertificateSignature(
			rebuild(t, protectedBytes, envelope(authData, clientDataJSON),
				bad),
			root, delegationcert.Secp256r1,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "low-s")
	})

	t.Run("envelope on a plain ES256 certificate", func(t *testing.T) {
		es256Protected, err := cbor.Marshal(map[int64]any{
			delegationcert.CoseHeaderAlg: delegationcert.CoseAlgES256,
		})
		require.NoError(t, err)
		err = delegationcert.VerifyCertificateSignature(
			rebuild(t, es256Protected, envelope(authData, clientDataJSON),
				signature),
			root, delegationcert.Secp256r1,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected WebAuthn envelope")
	})
}

// User verification is NOT enforced by default (ADR-0063 §4: the sealer
// has no grant in evidence), but is enforceable by a caller that does hold
// the grant. The captured assertion carries UV, so opting in must still
// pass; the negative case is covered by clearing the flag.
func TestWebauthnGoldenCertificateUserVerificationOption(t *testing.T) {
	g := loadWebauthnGolden(t)
	certBytes := goldenHex(t, g.Certificate.CoseSign1)
	root := goldenRootKey(t, g)

	require.NoError(t, delegationcert.VerifyCertificateSignature(
		certBytes, root, delegationcert.Secp256r1,
		delegationcert.WithRequireUserVerification(true),
	))

	authData := goldenHex(t, g.Certificate.AuthenticatorData)
	require.NotZero(t, authData[32]&0x04,
		"capture is expected to carry UV; the option test is vacuous "+
			"without it")
}
