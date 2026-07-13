package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

const phaseDLogID = "0123456789abcdef0123456789abcdef"

// buildSignedCert builds a delegation certificate binding delegPub over
// [start,end], signed by custodyPriv (the trust root) — mirrors the fixture in
// delegation_lease_verify_test.go.
func buildSignedCert(t *testing.T, custodyPriv *ecdsa.PrivateKey, delegPub *ecdsa.PublicKey, start, end uint64) []byte {
	t.Helper()
	x := make([]byte, 32)
	y := make([]byte, 32)
	delegPub.X.FillBytes(x)
	delegPub.Y.FillBytes(y)
	delegatedKey, err := delegationcert.NewDelegatedCoseKey(delegationcert.Secp256r1, x, y)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := kidFromECDSAPublicKey(&custodyPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := uint64(time.Now().Unix())
	expiresAt := issuedAt + 3600
	tbs, err := delegationcert.BuildDelegationToBeSigned(
		delegationcert.Secp256r1, kid,
		delegationcert.DelegationInput{
			LogID:        phaseDLogID,
			MmrStart:     start,
			MmrEnd:       end,
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
	cert, err := delegationcert.AssembleDelegationCert(tbs, sig)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func phaseDKeys(t *testing.T) (*DelegateKeySet, *ecdsa.PrivateKey) {
	t.Helper()
	local := localSeedProvider{secret: testSeed(t)}
	keys, err := LoadDelegateKeys(context.Background(), local, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Re-derive the epoch N-1 key for the rotation-overlap cases.
	prevSeed, _ := local.Seed(context.Background(), 2)
	prev, err := deriveDelegateKey(prevSeed, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	return keys, prev
}

func verifyCoverage(t *testing.T, custodyPriv *ecdsa.PrivateKey, keys *DelegateKeySet, cert []byte, mmrStart, mmrEnd uint64) error {
	t.Helper()
	pemStr := pemPublicKey(t, &custodyPriv.PublicKey)
	_, err := VerifyDelegationLease(
		LogSigningKey{PublicKeyPEM: pemStr, Alg: "ES256", AlgInt: coseAlgES256},
		&IssuerLeaseResponse{
			Certificate: cert,
			IssuedAt:    time.Now().UTC(),
			ExpiresAt:   time.Now().Add(time.Hour).UTC(),
		},
		LeaseVerificationInput{
			LogIdHex:   phaseDLogID,
			MMRStart:   mmrStart,
			MMREnd:     mmrEnd,
			Curve:      delegationcert.Secp256r1,
			CoverageOK: true,
			HeldKeys:   keys,
		},
		nil,
	)
	return err
}

// TestPhaseD_CoverageAcceptsWiderCert: a wide standing cert [0,1000] verifies a
// narrow seal window [5,7] (B5 coverage relaxation).
func TestPhaseD_CoverageAcceptsWiderCert(t *testing.T) {
	custody, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := phaseDKeys(t)
	cert := buildSignedCert(t, custody, &keys.Current().PublicKey, 0, 1000)
	if err := verifyCoverage(t, custody, keys, cert, 5, 7); err != nil {
		t.Fatalf("expected coverage accept, got %v", err)
	}
}

// TestPhaseD_CoverageRejectsUncoveredWindow: a window outside the cert range is
// rejected even though the key is held.
func TestPhaseD_CoverageRejectsUncoveredWindow(t *testing.T) {
	custody, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys, _ := phaseDKeys(t)
	cert := buildSignedCert(t, custody, &keys.Current().PublicKey, 0, 100)
	if err := verifyCoverage(t, custody, keys, cert, 200, 250); err == nil {
		t.Fatal("expected coverage rejection for uncovered window")
	}
}

// TestPhaseD_RejectsForeignKey: a cert bound to a key the sealer does not hold
// is rejected regardless of a valid signature and covering range.
func TestPhaseD_RejectsForeignKey(t *testing.T) {
	custody, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys, _ := phaseDKeys(t)
	foreign, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := buildSignedCert(t, custody, &foreign.PublicKey, 0, 1000)
	if err := verifyCoverage(t, custody, keys, cert, 5, 7); err == nil {
		t.Fatal("expected rejection of a cert bound to an unheld key")
	}
}

// TestPhaseD_AcceptsPreviousEpochKey: rotation overlap — a still-valid cert
// bound to the epoch N-1 key is accepted while the current epoch is N.
func TestPhaseD_AcceptsPreviousEpochKey(t *testing.T) {
	custody, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys, prev := phaseDKeys(t)
	cert := buildSignedCert(t, custody, &prev.PublicKey, 0, 1000)
	if err := verifyCoverage(t, custody, keys, cert, 5, 7); err != nil {
		t.Fatalf("expected acceptance of a cert bound to the N-1 key, got %v", err)
	}
}

// TestPhaseD_ResolveSigningKeyFromCert: the B4 resolution path — extract a
// cert's bound key and resolve it to the correct held private key (current and
// N-1), and refuse a foreign key.
func TestPhaseD_ResolveSigningKeyFromCert(t *testing.T) {
	custody, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys, prev := phaseDKeys(t)

	resolve := func(cert []byte) *ecdsa.PrivateKey {
		delegated, _, err := delegationcert.DelegatedKeyFromCertificate(cert)
		if err != nil {
			t.Fatalf("read cert delegated key: %v", err)
		}
		pub, err := ecdsaFromDelegatedCoseKey(delegated)
		if err != nil {
			t.Fatalf("decode delegated key: %v", err)
		}
		return keys.KeyFor(pub)
	}

	curCert := buildSignedCert(t, custody, &keys.Current().PublicKey, 0, 1000)
	if got := resolve(curCert); got == nil || got.D.Cmp(keys.Current().D) != 0 {
		t.Fatal("current cert did not resolve to the current private key")
	}
	prevCert := buildSignedCert(t, custody, &prev.PublicKey, 0, 1000)
	if got := resolve(prevCert); got == nil || got.D.Cmp(prev.D) != 0 {
		t.Fatal("N-1 cert did not resolve to the N-1 private key")
	}
	foreign, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	foreignCert := buildSignedCert(t, custody, &foreign.PublicKey, 0, 1000)
	if got := resolve(foreignCert); got != nil {
		t.Fatal("foreign cert must not resolve to any held key")
	}
}
