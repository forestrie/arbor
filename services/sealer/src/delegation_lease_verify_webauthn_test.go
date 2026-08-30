package sealer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/fxamacker/cbor/v2"
)

// spkiPEM encodes a public key the way the trust-root client serves it.
func spkiPEM(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(
		&pem.Block{Type: "PUBLIC KEY", Bytes: der},
	))
}

// buildWebauthnCertificate produces a synthetic ALG_ES256_WEBAUTHN
// delegation certificate signed the way an authenticator signs: over
// authenticatorData || SHA-256(clientDataJSON), with the certificate's
// Sig_structure digest carried as the WebAuthn challenge.
//
// Synthetic rather than captured because the sealer path needs control of
// log id, MMR range and expiry. The real-authenticator capture is asserted
// against separately, in the publishproof golden tests.
func buildWebauthnCertificate(
	t *testing.T,
	rootPriv *ecdsa.PrivateKey,
	delegatedPub *ecdsa.PublicKey,
	logIdHex string,
	mmrStart, mmrEnd uint64,
	expiresAt uint64,
	flags byte,
) []byte {
	t.Helper()

	x := make([]byte, 32)
	y := make([]byte, 32)
	delegatedPub.X.FillBytes(x)
	delegatedPub.Y.FillBytes(y)
	delegatedKey, err := delegationcert.NewDelegatedCoseKey(
		delegationcert.Secp256r1, x, y,
	)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := kidFromECDSAPublicKey(&rootPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	protected, err := cbor.Marshal(map[int64]any{
		delegationcert.CoseHeaderAlg: delegationcert.CoseAlgES256WebAuthn,
		delegationcert.CoseHeaderCty: delegationcert.DelegationContentType,
		delegationcert.CoseHeaderKid: kid,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cbor.Marshal(map[int64]any{
		delegationcert.PayloadLabelLogID:        logIdHex,
		delegationcert.PayloadLabelMmrStart:     mmrStart,
		delegationcert.PayloadLabelMmrEnd:       mmrEnd,
		delegationcert.PayloadLabelDelegatedKey: delegatedKey.ToCBORMap(),
		delegationcert.PayloadLabelConstraints:  map[string]any{},
		delegationcert.PayloadLabelSchemaVer:    int64(1),
		delegationcert.PayloadLabelIssuedAt:     expiresAt - 3600,
		delegationcert.PayloadLabelExpiresAt:    expiresAt,
		delegationcert.PayloadLabelDelegationID: make([]byte, 16),
	})
	if err != nil {
		t.Fatal(err)
	}

	sigStructure, err := cbor.Marshal([]any{
		"Signature1", protected, []byte{}, payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(sigStructure)
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	clientDataJSON := []byte(fmt.Sprintf(
		`{"type":"webauthn.get","challenge":"%s","origin":"https://example.test"}`,
		challenge,
	))
	authData := make([]byte, 37)
	authData[32] = flags

	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	assertionDigest := sha256.Sum256(signed)
	r, s, err := ecdsa.Sign(rand.Reader, rootPriv, assertionDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	sig = delegationcert.NormalizeES256SignatureLowS(sig)

	certBytes, err := cbor.Marshal([]any{
		protected,
		map[int64]any{
			delegationcert.CoseHeaderWebAuthnEnvelope: []any{
				authData, clientDataJSON,
			},
		},
		payload,
		sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	return certBytes
}

// A passkey-rooted lease verifies end to end at the sealer.
//
// Note the trust root is advertised as plain ES256: a passkey root is an
// ordinary 64-byte P-256 point, and ALG_ES256_WEBAUTHN describes the
// SIGNATURE, not the key. Only the certificate declares it. Before FOR-551
// this failed as "delegation cert signature invalid".
func TestVerifyDelegationLeaseAcceptsWebauthnCert(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	logIdHex := "0123456789abcdef0123456789abcdef"
	expiresAt := uint64(time.Now().Add(time.Hour).Unix())
	// UP|UV|BE|BS, as a real platform authenticator reports.
	cert := buildWebauthnCertificate(
		t, rootPriv, &delegPriv.PublicKey, logIdHex, 1, 10, expiresAt, 0x1d,
	)

	trustRoot := LogSigningKey{
		PublicKeyPEM: spkiPEM(t, &rootPriv.PublicKey),
		Alg:          "ES256",
		AlgInt:       delegationcert.CoseAlgES256,
	}
	issuerResp := &IssuerLeaseResponse{
		Certificate: cert,
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	req := LeaseVerificationInput{
		LogIdHex:           logIdHex,
		MMRStart:           1,
		MMREnd:             10,
		Curve:              delegationcert.Secp256r1,
		DelegatedPublicKey: &delegPriv.PublicKey,
	}

	info, err := VerifyDelegationLease(trustRoot, issuerResp, req, nil)
	if err != nil {
		t.Fatalf("passkey-rooted lease rejected: %v", err)
	}
	if info.PayloadLogID != logIdHex {
		t.Fatalf("log id mismatch: %s", info.PayloadLogID)
	}
}

// User verification is not enforced at the sealer (ADR-0063 §4): it holds
// a lease, not a grant, so it cannot read GF_REQUIRES_USER_VERIFICATION.
// A user-present-but-not-verified assertion must therefore be accepted
// here, and is backstopped on-chain at publish.
func TestVerifyDelegationLeaseAcceptsWebauthnCertWithoutUV(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	logIdHex := "0123456789abcdef0123456789abcdef"
	expiresAt := uint64(time.Now().Add(time.Hour).Unix())
	cert := buildWebauthnCertificate(
		t, rootPriv, &delegPriv.PublicKey, logIdHex, 1, 10, expiresAt,
		0x01, // UP only, no UV
	)

	_, err = VerifyDelegationLease(
		LogSigningKey{
			PublicKeyPEM: spkiPEM(t, &rootPriv.PublicKey),
			Alg:          "ES256",
			AlgInt:       delegationcert.CoseAlgES256,
		},
		&IssuerLeaseResponse{
			Certificate: cert,
			ExpiresAt:   time.Now().Add(time.Hour),
		},
		LeaseVerificationInput{
			LogIdHex:           logIdHex,
			MMRStart:           1,
			MMREnd:             10,
			Curve:              delegationcert.Secp256r1,
			DelegatedPublicKey: &delegPriv.PublicKey,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("UP-only assertion should be accepted at the sealer: %v", err)
	}
}

// User presence is always required, at every layer.
func TestVerifyDelegationLeaseRejectsWebauthnCertWithoutUP(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	logIdHex := "0123456789abcdef0123456789abcdef"
	expiresAt := uint64(time.Now().Add(time.Hour).Unix())
	cert := buildWebauthnCertificate(
		t, rootPriv, &delegPriv.PublicKey, logIdHex, 1, 10, expiresAt,
		0x00, // no flags at all
	)

	_, err = VerifyDelegationLease(
		LogSigningKey{
			PublicKeyPEM: spkiPEM(t, &rootPriv.PublicKey),
			Alg:          "ES256",
			AlgInt:       delegationcert.CoseAlgES256,
		},
		&IssuerLeaseResponse{
			Certificate: cert,
			ExpiresAt:   time.Now().Add(time.Hour),
		},
		LeaseVerificationInput{
			LogIdHex:           logIdHex,
			MMRStart:           1,
			MMREnd:             10,
			Curve:              delegationcert.Secp256r1,
			DelegatedPublicKey: &delegPriv.PublicKey,
		},
		nil,
	)
	if err == nil {
		t.Fatal("expected rejection when user presence is not set")
	}
}

// A certificate signed by a DIFFERENT passkey must not verify: the
// envelope must not become a way to bypass the root binding.
func TestVerifyDelegationLeaseRejectsWebauthnCertWrongRoot(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	logIdHex := "0123456789abcdef0123456789abcdef"
	expiresAt := uint64(time.Now().Add(time.Hour).Unix())
	cert := buildWebauthnCertificate(
		t, otherPriv, &delegPriv.PublicKey, logIdHex, 1, 10, expiresAt, 0x1d,
	)

	_, err = VerifyDelegationLease(
		LogSigningKey{
			PublicKeyPEM: spkiPEM(t, &rootPriv.PublicKey),
			Alg:          "ES256",
			AlgInt:       delegationcert.CoseAlgES256,
		},
		&IssuerLeaseResponse{
			Certificate: cert,
			ExpiresAt:   time.Now().Add(time.Hour),
		},
		LeaseVerificationInput{
			LogIdHex:           logIdHex,
			MMRStart:           1,
			MMREnd:             10,
			Curve:              delegationcert.Secp256r1,
			DelegatedPublicKey: &delegPriv.PublicKey,
		},
		nil,
	)
	if err == nil {
		t.Fatal("expected rejection for a certificate under another root")
	}
}

// Guards the premise the FOR-551 fix rests on: a 64-byte P-256 root is
// advertised as ES256, never as -65800. ALG_ES256_WEBAUTHN is a signature
// algorithm, not a key type, so a trust root must never carry it — if this
// ever changes, the sealer's ES256 branch stops being reached.
func TestWebauthnTrustRootStaysES256(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := LogSigningKey{
		PublicKeyPEM: spkiPEM(t, &rootPriv.PublicKey),
		Alg:          "ES256",
		AlgInt:       delegationcert.CoseAlgES256,
	}
	if root.IsKS256Root() {
		t.Fatal("a 64-byte P-256 root must not resolve as KS256")
	}
	if root.AlgInt == delegationcert.CoseAlgES256WebAuthn {
		t.Fatal("a trust root must never be advertised as ALG_ES256_WEBAUTHN")
	}
	if !algMatchesCurve(root.Alg, delegationcert.Secp256r1) {
		t.Fatal("ES256 root must match secp256r1")
	}
	// Sanity: the delegated key is a plain P-256 point either way.
	if new(big.Int).Set(rootPriv.PublicKey.X).BitLen() == 0 {
		t.Fatal("root key X must be set")
	}
}
