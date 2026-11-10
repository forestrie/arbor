package sealer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// verifiedLease builds a lease as VerifyDelegationLease admits it: the
// certificate range and the on-chain proof range are equal.
func verifiedLease(start, end uint64) *DelegationLease {
	return &DelegationLease{
		Info: &delegationcert.CertificateInfo{MMRStart: start, MMREnd: end},
		OnchainProof: &delegationcert.OnchainDelegationProof{
			MMRStart: start,
			MMREnd:   end,
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// A cached lease for [0,1] must not be reused for a later seal [0,3]: the
// on-chain proof binds mmrEnd in the root signature, and univocity reverts
// CheckpointIndexOutOfDelegationRange when claimedSize-1 > mmrEnd.
func TestLeaseCoversMMRRange_OnchainProof(t *testing.T) {
	lease := verifiedLease(0, 1)
	if !leaseCoversMMRRange(lease, 0, 1) {
		t.Fatal("expected [0,1] to cover [0,1]")
	}
	if !leaseCoversMMRRange(lease, 1, 1) {
		t.Fatal("expected [0,1] to cover [1,1]")
	}
	if leaseCoversMMRRange(lease, 0, 3) {
		t.Fatal("expected [0,1] not to cover [0,3]")
	}
}

func TestLeaseCoversMMRRange_OnchainProofInterior(t *testing.T) {
	lease := verifiedLease(0, 3)
	if !leaseCoversMMRRange(lease, 1, 1) {
		t.Fatal("expected [0,3] to cover [1,1]")
	}
	if !leaseCoversMMRRange(lease, 0, 3) {
		t.Fatal("expected [0,3] to cover [0,3]")
	}
}

// Coverage is the certificate's range, the one offline verification checks.
// An on-chain proof wider than the certificate must not extend it: a
// checkpoint sealed past the certificate would publish on-chain yet fail
// offline verification.
func TestLeaseCoversMMRRange_WiderProofDoesNotExtendCoverage(t *testing.T) {
	lease := verifiedLease(0, 1)
	lease.OnchainProof.MMREnd = 1000
	if !leaseCoversMMRRange(lease, 0, 1) {
		t.Fatal("expected certificate [0,1] to cover [0,1]")
	}
	if leaseCoversMMRRange(lease, 0, 3) {
		t.Fatal("a proof wider than the certificate must not cover [0,3]")
	}
}

func TestEnsureValidForLog_RejectsCachedLeaseOutsideRange(t *testing.T) {
	logID := "abcdef0123456789abcdef0123456789"
	mgr := NewDelegationLeaseManager(
		&stubAuthorityResolver{},
		&pendingIssuerStub{},
		time.Hour,
		time.Minute,
	)
	mgr.SetDelegateKeys(standingKeys(t))
	lease := verifiedLease(0, 1)
	entry := &leaseEntry{key: logID, lease: lease}
	elem := mgr.lru.PushFront(entry)
	mgr.leases[logID] = elem

	// Request for [0,3] must not return the cached [0,1] lease; with the
	// pending issuer stub it surfaces ErrDelegationPending after eviction.
	_, err := mgr.EnsureValidForLog(
		t.Context(),
		NewHTTPClient(nil),
		nil,
		"secp256r1",
		logID,
		0,
		3,
	)
	if !errors.Is(err, ErrDelegationPending) {
		t.Fatalf("got %v want ErrDelegationPending (cached lease must be evicted)", err)
	}
	if _, ok := mgr.leases[logID]; ok {
		t.Fatal("expected non-covering cached lease to be evicted")
	}
}

// certFallbackLease builds a lease with no on-chain proof from a parsed
// certificate, the range leaseCoversMMRRange reads.
func certFallbackLease(t *testing.T, cert []byte) *DelegationLease {
	t.Helper()
	info, err := delegationcert.ParseCertificate(cert)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return &DelegationLease{CertBytes: cert, Info: info, ExpiresAt: time.Now().Add(time.Hour)}
}

// TestLeaseCoversMMRRange_CertFallbackWide pins the uint64 range end to end
// on the certificate fallback path: bounds above 2^32 and 2^53 and at
// 2^64-1 compare exactly, with no decimal round trip.
func TestLeaseCoversMMRRange_CertFallbackWide(t *testing.T) {
	custody, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deleg, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		start, end uint64
	}{
		{"2^32+1", 1<<32 + 1, 1<<32 + 1},
		{"2^53+1", 1<<53 + 1, 1<<53 + 1},
		{"2^64-1", math.MaxUint64, math.MaxUint64},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lease := certFallbackLease(t, buildSignedCert(t, custody, deleg.Public().(*ecdsa.PublicKey), c.start, c.end))
			if !leaseCoversMMRRange(lease, c.start, c.end) {
				t.Fatalf("expected [%d,%d] to cover itself", c.start, c.end)
			}
			if leaseCoversMMRRange(lease, c.start-1, c.end) {
				t.Fatalf("expected [%d,%d] not to cover start-1", c.start, c.end)
			}
			if c.end < math.MaxUint64 && leaseCoversMMRRange(lease, c.start, c.end+1) {
				t.Fatalf("expected [%d,%d] not to cover end+1", c.start, c.end)
			}
		})
	}
}

// TestLeaseCoversMMRRange_WebAuthnGolden2Pow40 runs the real-authenticator
// golden certificate (mmrEnd = 2^40) through ParseCertificate and the
// certificate fallback range check.
func TestLeaseCoversMMRRange_WebAuthnGolden2Pow40(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "pkgs", "publishproof", "testdata", "webauthn-real-authenticator-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Certificate struct {
			CoseSign1 string `json:"coseSign1"`
		} `json:"certificate"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	cert, err := hex.DecodeString(g.Certificate.CoseSign1)
	if err != nil {
		t.Fatal(err)
	}
	lease := certFallbackLease(t, cert)
	const end = uint64(1) << 40
	if !leaseCoversMMRRange(lease, 0, end) {
		t.Fatal("expected the golden [0,2^40] to cover [0,2^40]")
	}
	if !leaseCoversMMRRange(lease, end, end) {
		t.Fatal("expected the golden [0,2^40] to cover [2^40,2^40]")
	}
	if leaseCoversMMRRange(lease, 0, end+1) {
		t.Fatal("expected the golden [0,2^40] not to cover 2^40+1")
	}
}

// A lease with no parsed certificate covers nothing, even with an on-chain
// proof: a certificate that failed to parse never yields an Info, so the
// check must fail closed rather than read zero-valued bounds or trust the
// proof's range alone.
func TestLeaseCoversMMRRange_NoInfoCoversNothing(t *testing.T) {
	lease := &DelegationLease{ExpiresAt: time.Now().Add(time.Hour)}
	if leaseCoversMMRRange(lease, 0, 0) {
		t.Fatal("a lease without proof or certificate info must not cover [0,0]")
	}
	lease.OnchainProof = &delegationcert.OnchainDelegationProof{MMRStart: 0, MMREnd: 10}
	if leaseCoversMMRRange(lease, 0, 0) {
		t.Fatal("a lease with only an on-chain proof must not cover [0,0]")
	}
}
