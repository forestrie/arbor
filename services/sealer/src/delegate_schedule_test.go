package sealer

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestLoadDelegateKeysWithRetry_EventualSuccess proves the boot retry loop keeps
// trying a failing seed load and wires the keys once it succeeds (FOR-390 phase
// J1 — custodian required at boot, retry-not-die, any-order startup).
func TestLoadDelegateKeysWithRetry_EventualSuccess(t *testing.T) {
	logger, _ := NewLogger(0)
	local := localSeedProvider{secret: testSeed(t)}
	want, err := LoadDelegateKeys(context.Background(), local, 2)
	if err != nil {
		t.Fatalf("load keys: %v", err)
	}

	calls := 0
	load := func() (*DelegateKeySet, error) {
		calls++
		if calls < 3 {
			return nil, fmt.Errorf("custodian not ready (attempt %d)", calls)
		}
		return want, nil
	}

	got := make(chan *DelegateKeySet, 1)
	// Tiny backoff so the test is fast; the loop waits before each attempt.
	go loadDelegateKeysWithRetry(
		context.Background(), logger, load,
		func(k *DelegateKeySet) { got <- k },
		time.Millisecond, 5*time.Millisecond,
	)

	select {
	case k := <-got:
		if k != want {
			t.Fatal("onReady got the wrong key set")
		}
		if calls != 3 {
			t.Fatalf("expected 3 attempts (2 fail, 1 ok), got %d", calls)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry loop never reached success")
	}
}

// TestLoadDelegateKeysWithRetry_CancelStops confirms a cancelled context ends
// the retry loop without ever invoking onReady.
func TestLoadDelegateKeysWithRetry_CancelStops(t *testing.T) {
	logger, _ := NewLogger(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done

	readyCalled := false
	loadDelegateKeysWithRetry(
		ctx, logger,
		func() (*DelegateKeySet, error) { return nil, fmt.Errorf("down") },
		func(*DelegateKeySet) { readyCalled = true },
		time.Millisecond, 5*time.Millisecond,
	)
	if readyCalled {
		t.Fatal("onReady must not be called after ctx cancellation")
	}
}
