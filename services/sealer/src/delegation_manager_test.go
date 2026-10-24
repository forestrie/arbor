package sealer

import (
	"context"
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
