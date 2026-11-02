package sealer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
		LogSigningKey{PublicKeyPEM: pemStr, Alg: "ES256", AlgInt: coseAlgES256},
		issuerResp,
		LeaseVerificationInput{
			LogIdHex: logIdHex,
			MMRStart: 1,
			MMREnd:   10,
			Curve:    delegationcert.Secp256r1,
			HeldKeys: heldKeysFor(t, delegPriv),
		},
		nil,
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
		LogSigningKey{PublicKeyPEM: pemStr, Alg: "ES256", AlgInt: coseAlgES256},
		issuerResp,
		LeaseVerificationInput{
			LogIdHex: logIdHex,
			MMRStart: 1,
			MMREnd:   10,
			Curve:    delegationcert.Secp256r1,
			HeldKeys: heldKeysFor(t, otherPriv),
		},
		nil,
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

// verifyLeaseWithProof signs a certificate over [1,10] and verifies an issuer
// response carrying proof against the seal window [1,10].
func verifyLeaseWithProof(t *testing.T, proof *delegationcert.OnchainDelegationProof) error {
	t.Helper()
	custody, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deleg, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, err = VerifyDelegationLease(
		LogSigningKey{PublicKeyPEM: pemPublicKey(t, &custody.PublicKey), Alg: "ES256", AlgInt: coseAlgES256},
		&IssuerLeaseResponse{
			Certificate:  buildSignedCert(t, custody, &deleg.PublicKey, 1, 10),
			OnchainProof: proof,
			IssuedAt:     now,
			ExpiresAt:    now.Add(time.Hour),
		},
		LeaseVerificationInput{
			LogIdHex: phaseDLogID,
			MMRStart: 1,
			MMREnd:   10,
			Curve:    delegationcert.Secp256r1,
			HeldKeys: heldKeysFor(t, deleg),
		},
		nil,
	)
	return err
}

// The on-chain proof's range must equal the certificate's: univocity checks
// the proof at publication, offline verification checks the certificate, and
// a lease is reused for any window its range covers.
func TestVerifyDelegationLease_OnchainProofRange(t *testing.T) {
	cases := []struct {
		name       string
		proof      *delegationcert.OnchainDelegationProof
		wantErr    error
		wantAccept bool
	}{
		{"nil proof", nil, nil, true},
		{"matching proof", &delegationcert.OnchainDelegationProof{MMRStart: 1, MMREnd: 10}, nil, true},
		{"wider end", &delegationcert.OnchainDelegationProof{MMRStart: 1, MMREnd: 1000}, ErrOnchainProofRangeMismatch, false},
		{"wider start", &delegationcert.OnchainDelegationProof{MMRStart: 0, MMREnd: 10}, ErrOnchainProofRangeMismatch, false},
		{"narrower", &delegationcert.OnchainDelegationProof{MMRStart: 2, MMREnd: 9}, ErrOnchainProofRangeMismatch, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := verifyLeaseWithProof(t, c.proof)
			if c.wantAccept {
				if err != nil {
					t.Fatalf("expected lease accepted, got %v", err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("got %v, want %v", err, c.wantErr)
			}
		})
	}
}
