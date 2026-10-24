package sealer

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// With no standing delegate keys installed there is nothing to request a
// certificate for: the on-demand ephemeral-key path was removed
// (devdocs plan-2609-12 slice 10), so the manager refuses without calling
// the issuer.
func TestEnsureValidForLog_NoStandingKeysRefusesWithoutIssuing(t *testing.T) {
	issuer := &pendingIssuerStub{}
	mgr := NewDelegationLeaseManager(&stubTrustRootClient{}, issuer, time.Hour, time.Minute)

	_, err := mgr.EnsureValidForLog(
		t.Context(), NewHTTPClient(nil), nil, "secp256r1",
		"0123456789abcdef0123456789abcdef", 0, 3,
	)
	if !errors.Is(err, ErrNoStandingDelegateKeys) {
		t.Fatalf("got %v want ErrNoStandingDelegateKeys", err)
	}
	if len(issuer.requests) != 0 {
		t.Fatalf("issuer called %d times, want 0", len(issuer.requests))
	}
}

// With standing keys installed the request carries the current standing key
// over the true seal window, unpadded.
func TestEnsureValidForLog_RequestsCurrentStandingKeyOverTrueWindow(t *testing.T) {
	keys, _ := phaseDKeys(t)
	issuer := &pendingIssuerStub{}
	mgr := NewDelegationLeaseManager(&stubTrustRootClient{}, issuer, time.Hour, time.Minute)
	mgr.SetDelegateKeys(keys)

	_, err := mgr.EnsureValidForLog(
		t.Context(), NewHTTPClient(nil), nil, "secp256r1",
		"0123456789abcdef0123456789abcdef", 7, 21,
	)
	if !errors.Is(err, ErrDelegationPending) {
		t.Fatalf("got %v want ErrDelegationPending", err)
	}
	if len(issuer.requests) != 1 {
		t.Fatalf("issuer called %d times, want 1", len(issuer.requests))
	}
	req := issuer.requests[0]
	if req.MMRStart != 7 || req.MMREnd != 21 {
		t.Fatalf("requested [%d,%d], want [7,21]", req.MMRStart, req.MMREnd)
	}
	got, _, err := delegationcert.ParseDelegatedPublicKeyFromCBOR(req.DelegatedPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := ecdsaFromDelegatedCoseKey(got)
	if err != nil {
		t.Fatal(err)
	}
	if !gotPub.Equal(&keys.Current().PublicKey) {
		t.Fatal("request did not carry the current standing key")
	}
}

// standingKeys is a standing delegate key set (epochs 2 and 1) from the
// local test seed, for tests that only need some held keys.
func standingKeys(t *testing.T) *DelegateKeySet {
	t.Helper()
	keys, err := LoadDelegateKeys(t.Context(), localSeedProvider{secret: testSeed(t)}, 2)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// requestLeaseForTest requests a lease for the standing keys through the
// legacy trust-root seam (no authority resolver, no ERC-1271 verifier).
func requestLeaseForTest(
	t *testing.T,
	ctx context.Context,
	httpClient *HTTPClient,
	trustRoot TrustRootClient,
	issuer DelegationIssuer,
	curve string,
	ttl time.Duration,
	logIdHex string,
	mmrStart, mmrEnd uint64,
) (*DelegationLease, error) {
	t.Helper()
	return requestLogDelegationLease(
		ctx, httpClient, trustRoot, nil, issuer, nil, curve, ttl,
		logIdHex, mmrStart, mmrEnd, standingKeys(t),
	)
}

// heldKeysFor is a key set holding only priv, for verifier tests that sign a
// certificate to a key of their own choosing.
func heldKeysFor(t *testing.T, priv *ecdsa.PrivateKey) *DelegateKeySet {
	t.Helper()
	h, err := pubkeyHashHex(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &DelegateKeySet{
		byPubkeyHash: map[string]*ecdsa.PrivateKey{h: priv},
		entries:      []delegateKeyEntry{{epoch: 1, priv: priv}},
		current:      priv,
		currentEpoch: 1,
	}
}

// TestEnsureValidForLog_CachedWideLeaseServesGrownWindows is the FOR-386
// regression, carried over from the removed range-pad tests: the cache must
// be consulted with the caller's TRUE seal window (the first cut widened the
// lookup window itself, advancing the requested end past the cached cert on
// every append and defeating the cache by construction). A cached wide lease,
// such as one from a standing key's advance certificate, must serve
// subsequent grown windows with ZERO issuer calls until the log outgrows it;
// an outgrown window goes to issuance over the true window.
func TestEnsureValidForLog_CachedWideLeaseServesGrownWindows(t *testing.T) {
	logID := "abcdef0123456789abcdef0123456789"
	issuer := &pendingIssuerStub{}
	mgr := NewDelegationLeaseManager(&stubTrustRootClient{}, issuer, time.Hour, time.Minute)
	mgr.SetDelegateKeys(standingKeys(t))

	cached := &DelegationLease{
		OnchainProof: &delegationcert.OnchainDelegationProof{MMRStart: 0, MMREnd: 1000},
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	elem := mgr.lru.PushFront(&leaseEntry{key: logID, lease: cached})
	mgr.leases[logID] = elem

	for _, w := range [][2]uint64{{7, 9}, {9, 12}, {12, 1000}} {
		lease, err := mgr.EnsureValidForLog(t.Context(), NewHTTPClient(nil), nil, "secp256r1", logID, w[0], w[1])
		if err != nil {
			t.Fatalf("window [%d,%d]: %v", w[0], w[1], err)
		}
		if lease != cached {
			t.Fatalf("window [%d,%d]: expected cached lease", w[0], w[1])
		}
	}
	if len(issuer.requests) != 0 {
		t.Fatalf("issuer called %d times for covered windows, want 0", len(issuer.requests))
	}

	_, err := mgr.EnsureValidForLog(t.Context(), NewHTTPClient(nil), nil, "secp256r1", logID, 1000, 1002)
	if !errors.Is(err, ErrDelegationPending) || len(issuer.requests) != 1 {
		t.Fatalf("outgrown window: expected pending issuance, err=%v calls=%d", err, len(issuer.requests))
	}
	if r := issuer.requests[0]; r.MMRStart != 1000 || r.MMREnd != 1002 {
		t.Errorf("issuance request [%d,%d], want true window [1000,1002]", r.MMRStart, r.MMREnd)
	}
}
