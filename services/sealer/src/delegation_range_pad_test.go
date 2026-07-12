package sealer

import (
	"context"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// capturingIssuerStub records issuance requests and returns pending; used to
// assert whether (and with what range) issuance was attempted.
type capturingIssuerStub struct {
	requests []IssuerLeaseRequest
}

func (s *capturingIssuerStub) IssueForLog(_ context.Context, req IssuerLeaseRequest) (*IssuerLeaseResponse, error) {
	s.requests = append(s.requests, req)
	return nil, ErrDelegationPending
}

// TestEnsureValidForLog_CachedPaddedLeaseServesGrownWindows is THE FOR-386
// regression: the cache must be consulted with the caller's TRUE seal window
// (the first-cut padded the lookup window itself, advancing the requested end
// past the cached cert on every append and defeating the cache by
// construction — measured live as one issuance round-trip per append). A
// cached wide lease must serve subsequent grown windows with ZERO issuer
// calls until the log outgrows the pad.
func TestEnsureValidForLog_CachedPaddedLeaseServesGrownWindows(t *testing.T) {
	logID := "abcdef0123456789abcdef0123456789"
	issuer := &capturingIssuerStub{}
	mgr := NewDelegationLeaseManager(&stubTrustRootClient{}, issuer, time.Hour, time.Minute)
	mgr.SetRangePad(65536)

	// Simulate the lease issued for the first seal [0, 7] with the pad applied.
	cached := &DelegationLease{
		OnchainProof: &delegationcert.OnchainDelegationProof{
			MMRStart: 0,
			MMREnd:   paddedRangeEnd(7, 65536),
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	elem := mgr.lru.PushFront(&leaseEntry{key: logID, lease: cached})
	mgr.leases[logID] = elem

	// Subsequent appends: windows advance but stay inside the pad — every one
	// must be served from cache.
	for _, w := range [][2]uint64{{7, 9}, {9, 12}, {12, 500}} {
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

	// Outgrown window: must go to issuance, and the new request must itself be
	// padded.
	_, err := mgr.EnsureValidForLog(t.Context(), NewHTTPClient(nil), nil, "secp256r1", logID, 65543, 65545)
	if err == nil || len(issuer.requests) != 1 {
		t.Fatalf("outgrown window: expected pending issuance, err=%v calls=%d", err, len(issuer.requests))
	}
	if got, want := issuer.requests[0].MMREnd, paddedRangeEnd(65545, 65536); got != want {
		t.Errorf("issuance request MMREnd = %d, want padded %d", got, want)
	}
	if issuer.requests[0].MMRStart != 65543 {
		t.Errorf("issuance request MMRStart = %d, want 65543 (true window start)", issuer.requests[0].MMRStart)
	}
}

// TestPaddedRangeEnd covers the FOR-386 request-widening helper, including the
// uint64 overflow clamp.
func TestPaddedRangeEnd(t *testing.T) {
	if got := paddedRangeEnd(10, 0); got != 10 {
		t.Errorf("pad 0: got %d, want 10 (legacy per-seal window)", got)
	}
	if got := paddedRangeEnd(10, 65536); got != 65546 {
		t.Errorf("pad 65536: got %d, want 65546", got)
	}
	max := ^uint64(0)
	if got := paddedRangeEnd(max-5, 100); got != max {
		t.Errorf("overflow: got %d, want clamp to max", got)
	}
	if got := paddedRangeEnd(max, 1); got != max {
		t.Errorf("overflow at max: got %d, want max", got)
	}
}

// TestPaddedLeaseCoversSubsequentSealWindows pins the property FOR-386 relies
// on: a lease issued for a padded range [0, sealEnd+pad] keeps covering later
// seal windows (whose mmrStart advances past earlier checkpoints) until the
// log outgrows the pad — so the cache serves every append in between and
// issuance leaves the hot path.
func TestPaddedLeaseCoversSubsequentSealWindows(t *testing.T) {
	const pad = 65536
	// First seal window [0, 7]; the request (and hence the cert/lease) covers
	// [0, 7+pad].
	lease := &DelegationLease{
		OnchainProof: &delegationcert.OnchainDelegationProof{
			MMRStart: 0,
			MMREnd:   paddedRangeEnd(7, pad),
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	// Later appends: baseState advances, windows grow — all inside the pad.
	for _, w := range [][2]uint64{{7, 15}, {15, 100}, {100, 7 + pad}} {
		if !leaseCoversMMRRange(lease, w[0], w[1]) {
			t.Errorf("padded lease should cover subsequent window [%d,%d]", w[0], w[1])
		}
	}
	// Outgrown: the seal window passes the padded end — must miss the cache
	// (a stale wide lease must never sign past its authorized range).
	if leaseCoversMMRRange(lease, 7+pad, 7+pad+1) {
		t.Error("padded lease must not cover a window past its authorized end")
	}
}

// TestConfigDelegationRangePad covers the env default and override.
func TestConfigDelegationRangePad(t *testing.T) {
	t.Setenv("DELEGATION_RANGE_PAD", "")
	if got := LoadConfig().DelegationRangePad; got != 65536 {
		t.Errorf("default: got %d, want 65536", got)
	}
	t.Setenv("DELEGATION_RANGE_PAD", "0")
	if got := LoadConfig().DelegationRangePad; got != 0 {
		t.Errorf("explicit 0 (disable): got %d, want 0", got)
	}
	t.Setenv("DELEGATION_RANGE_PAD", "1048576")
	if got := LoadConfig().DelegationRangePad; got != 1048576 {
		t.Errorf("override: got %d, want 1048576", got)
	}
	t.Setenv("DELEGATION_RANGE_PAD", "not-a-number")
	if got := LoadConfig().DelegationRangePad; got != 65536 {
		t.Errorf("garbage falls back to default: got %d, want 65536", got)
	}
}
