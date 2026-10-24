package sealer

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// The consumer-start hook runs only once the keys are installed, and exactly
// once (devdocs plan-2609-12 ruling D1 (a), slice 10).
func TestRunWhenInstalled_StartsOnlyAfterKeysInstalled(t *testing.T) {
	installed := NewDelegateKeysInstalled()
	var starts atomic.Int32
	done := installed.RunWhenInstalled(context.Background(), func() { starts.Add(1) })

	time.Sleep(20 * time.Millisecond)
	if n := starts.Load(); n != 0 {
		t.Fatalf("started %d times before keys installed, want 0", n)
	}

	installed.fire()
	installed.fire()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("start hook never ran after keys installed")
	}
	if n := starts.Load(); n != 1 {
		t.Fatalf("started %d times, want 1", n)
	}
}

// Shutdown before the keys install never starts consuming.
func TestRunWhenInstalled_CancelledNeverStarts(t *testing.T) {
	installed := NewDelegateKeysInstalled()
	ctx, cancel := context.WithCancel(context.Background())
	var starts atomic.Int32
	done := installed.RunWhenInstalled(ctx, func() { starts.Add(1) })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gate goroutine did not exit on cancel")
	}
	installed.fire()
	time.Sleep(10 * time.Millisecond)
	if n := starts.Load(); n != 0 {
		t.Fatalf("started %d times after cancel, want 0", n)
	}
}
