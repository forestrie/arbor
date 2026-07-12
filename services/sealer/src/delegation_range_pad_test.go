package sealer

import (
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

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
