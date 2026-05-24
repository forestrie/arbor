package sealer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

func TestVerifyDelegationLease_acceptsValidCert(t *testing.T) {
	custodyPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x := make([]byte, 32)
	y := make([]byte, 32)
	delegPriv.PublicKey.X.FillBytes(x)
	delegPriv.PublicKey.Y.FillBytes(y)
	delegatedKey, err := delegationcert.NewDelegatedCoseKey(delegationcert.Secp256r1, x, y)
	if err != nil {
		t.Fatal(err)
	}

	kid, err := kidFromECDSAPublicKey(&custodyPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	logIdHex := "0123456789abcdef0123456789abcdef"
	issuedAt := uint64(time.Now().Unix())
	expiresAt := issuedAt + 3600
	tbs, err := delegationcert.BuildDelegationToBeSigned(
		delegationcert.Secp256r1,
		kid,
		delegationcert.DelegationInput{
			LogID:        logIdHex,
			MmrStart:     1,
			MmrEnd:       10,
			DelegatedKey: delegatedKey,
			Constraints:  map[string]any{},
			DelegationID: make([]byte, 16),
			IssuedAt:     issuedAt,
			ExpiresAt:    expiresAt,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, custodyPriv, tbs.SigStructureDigest)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])
	certBytes, err := delegationcert.AssembleDelegationCert(tbs, sig)
	if err != nil {
		t.Fatal(err)
	}

	pemStr := pemPublicKey(t, &custodyPriv.PublicKey)

	issuerResp := &IssuerLeaseResponse{
		Certificate: certBytes,
		IssuedAt:    time.Unix(int64(issuedAt), 0).UTC(),
		ExpiresAt:   time.Unix(int64(expiresAt), 0).UTC(),
	}
	_, err = VerifyDelegationLease(
		LogSigningKey{PublicKeyPEM: pemStr, Alg: "ES256"},
		issuerResp,
		LeaseVerificationInput{
			LogIdHex:           logIdHex,
			MMRStart:           1,
			MMREnd:             10,
			Curve:              delegationcert.Secp256r1,
			DelegatedPublicKey: &delegPriv.PublicKey,
		},
	)
	if err != nil {
		t.Fatalf("expected valid lease, got %v", err)
	}
}

func TestVerifyDelegationLease_rejectsWrongDelegatedKey(t *testing.T) {
	custodyPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x := make([]byte, 32)
	y := make([]byte, 32)
	delegPriv.PublicKey.X.FillBytes(x)
	delegPriv.PublicKey.Y.FillBytes(y)
	delegatedKey, err := delegationcert.NewDelegatedCoseKey(delegationcert.Secp256r1, x, y)
	if err != nil {
		t.Fatal(err)
	}

	kid, err := kidFromECDSAPublicKey(&custodyPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	logIdHex := "0123456789abcdef0123456789abcdef"
	issuedAt := uint64(time.Now().Unix())
	expiresAt := issuedAt + 3600
	tbs, err := delegationcert.BuildDelegationToBeSigned(
		delegationcert.Secp256r1,
		kid,
		delegationcert.DelegationInput{
			LogID:        logIdHex,
			MmrStart:     1,
			MmrEnd:       10,
			DelegatedKey: delegatedKey,
			Constraints:  map[string]any{},
			DelegationID: make([]byte, 16),
			IssuedAt:     issuedAt,
			ExpiresAt:    expiresAt,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, custodyPriv, tbs.SigStructureDigest)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])
	certBytes, err := delegationcert.AssembleDelegationCert(tbs, sig)
	if err != nil {
		t.Fatal(err)
	}

	pemStr := pemPublicKey(t, &custodyPriv.PublicKey)

	issuerResp := &IssuerLeaseResponse{
		Certificate: certBytes,
		IssuedAt:    time.Unix(int64(issuedAt), 0).UTC(),
		ExpiresAt:   time.Unix(int64(expiresAt), 0).UTC(),
	}
	_, err = VerifyDelegationLease(
		LogSigningKey{PublicKeyPEM: pemStr, Alg: "ES256"},
		issuerResp,
		LeaseVerificationInput{
			LogIdHex:           logIdHex,
			MMRStart:           1,
			MMREnd:             10,
			Curve:              delegationcert.Secp256r1,
			DelegatedPublicKey: &otherPriv.PublicKey,
		},
	)
	if err == nil {
		t.Fatal("expected delegated key mismatch error")
	}
}

func pemPublicKey(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
