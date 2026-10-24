package sealer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// TestStartDelegateKeys_InstalledOnlyOnceKeysLoad proves the D1 gate
// (devdocs plan-2609-12 slice 10): until a seed load succeeds the sealer
// reports not ready and has no keys to lease with; once it succeeds the keys
// are installed and the installed signal fires, which is what lets main
// start the queue consumer and resync.
func TestStartDelegateKeys_InstalledOnlyOnceKeysLoad(t *testing.T) {
	logger, _ := NewLogger(0)
	keys, err := LoadDelegateKeys(context.Background(), localSeedProvider{secret: testSeed(t)}, 2)
	if err != nil {
		t.Fatalf("load keys: %v", err)
	}
	release := make(chan struct{})
	load := func() (*DelegateKeySet, error) {
		select {
		case <-release:
			return keys, nil
		default:
			return nil, fmt.Errorf("custodian not ready")
		}
	}
	issuer := &pendingIssuerStub{}
	mgr := NewDelegationLeaseManager(&stubTrustRootClient{}, issuer, time.Hour, time.Minute)

	installed := NewDelegateKeysInstalled()
	startDelegateKeys(context.Background(), logger, load, mgr, installed, time.Millisecond, 5*time.Millisecond)

	time.Sleep(20 * time.Millisecond) // several failed attempts
	if installed.Installed() {
		t.Fatal("installed before any load succeeded")
	}
	if code := readyzStatus(t, installed); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d before keys, want 503", code)
	}
	if _, err := mgr.EnsureValidForLog(t.Context(), NewHTTPClient(nil), nil, "secp256r1",
		"0123456789abcdef0123456789abcdef", 0, 1); !errors.Is(err, ErrNoStandingDelegateKeys) {
		t.Fatalf("lease before keys: got %v want ErrNoStandingDelegateKeys", err)
	}

	close(release)
	select {
	case <-installed.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("installed signal never fired")
	}
	if code := readyzStatus(t, installed); code != http.StatusOK {
		t.Fatalf("/readyz = %d after keys, want 200", code)
	}
	if _, err := mgr.EnsureValidForLog(t.Context(), NewHTTPClient(nil), nil, "secp256r1",
		"0123456789abcdef0123456789abcdef", 0, 1); !errors.Is(err, ErrDelegationPending) {
		t.Fatalf("lease after keys: got %v want ErrDelegationPending", err)
	}
}

// TestStartDelegateKeys_FirstAttemptInline confirms a healthy seed source
// installs keys before startDelegateKeys returns, so a normal boot starts
// consuming without waiting for a retry tick.
func TestStartDelegateKeys_FirstAttemptInline(t *testing.T) {
	logger, _ := NewLogger(0)
	keys, err := LoadDelegateKeys(context.Background(), localSeedProvider{secret: testSeed(t)}, 2)
	if err != nil {
		t.Fatalf("load keys: %v", err)
	}
	mgr := NewDelegationLeaseManager(&stubTrustRootClient{}, &pendingIssuerStub{}, time.Hour, time.Minute)
	installed := NewDelegateKeysInstalled()
	startDelegateKeys(context.Background(), logger,
		func() (*DelegateKeySet, error) { return keys, nil }, mgr, installed, time.Hour, time.Hour)
	if !installed.Installed() {
		t.Fatal("first successful attempt must install inline")
	}
}

func readyzStatus(t *testing.T, installed *DelegateKeysInstalled) int {
	t.Helper()
	rec := httptest.NewRecorder()
	installed.ReadyzHandler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return rec.Code
}

// A loader that reports success with no keys must not open the gate: it is
// retried like a failure, so the consumer never starts without keys.
func TestStartDelegateKeys_NilKeysRetried(t *testing.T) {
	logger, _ := NewLogger(0)
	keys := standingKeys(t)
	calls := 0
	load := func() (*DelegateKeySet, error) {
		calls++
		if calls < 3 {
			return nil, nil
		}
		return keys, nil
	}
	mgr := NewDelegationLeaseManager(&stubTrustRootClient{}, &pendingIssuerStub{}, time.Hour, time.Minute)
	installed := NewDelegateKeysInstalled()
	startDelegateKeys(context.Background(), logger, load, mgr, installed, time.Millisecond, 5*time.Millisecond)
	if installed.Installed() {
		t.Fatal("installed after a load returned no keys")
	}
	select {
	case <-installed.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("never installed")
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}
