package sealer

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestDelegateKeyRunner_BootRetryEventualSuccess proves the boot retry keeps
// trying a failing seed load and installs the keys once it succeeds (FOR-390
// phase J1: custodian required at boot, retry-not-die, any-order startup).
func TestDelegateKeyRunner_BootRetryEventualSuccess(t *testing.T) {
	want := localKeys(t, 2)
	calls := 0
	h := newRunnerHarness(t)
	h.r.load = func(context.Context) (*DelegateKeySet, error) {
		calls++
		if calls < 3 {
			return nil, fmt.Errorf("custodian not ready (attempt %d)", calls)
		}
		return want, nil
	}
	h.start(nil)

	waitFor(t, "keys installed", func() bool { return h.installedCount() == 1 })
	if h.installed() != want {
		t.Fatal("installed the wrong key set")
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts (2 fail, 1 ok), got %d", calls)
	}
}

// TestDelegateKeyRunner_CancelStops confirms a cancelled context ends the
// boot retry without installing anything.
func TestDelegateKeyRunner_CancelStops(t *testing.T) {
	h := newRunnerHarness(t)
	h.r.load = func(context.Context) (*DelegateKeySet, error) { return nil, fmt.Errorf("down") }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.r.run(ctx, nil) // returns promptly
	if h.installedCount() != 0 {
		t.Fatal("must not install after ctx cancellation")
	}
	if ok, _ := h.r.readiness.Ready(); ok {
		t.Fatal("must not be ready without keys")
	}
}

// localKeys loads a deterministic key set from the test-only local seed.
func localKeys(t *testing.T, epoch uint32) *DelegateKeySet {
	t.Helper()
	keys, err := LoadDelegateKeys(context.Background(), localSeedProvider{secret: testSeed(t)}, epoch)
	if err != nil {
		t.Fatalf("load keys: %v", err)
	}
	return keys
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}
