package sealer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// /readyz answers 503 until keys are installed and the current key's first
// assertion succeeded, then latches 200 (devdocs plan-2609-12 slice 05,
// ruling 5).
func TestDelegateKeyReadiness_Readyz(t *testing.T) {
	r := NewDelegateKeyReadiness()
	code, body := readyz(t, r)
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "not installed") {
		t.Fatalf("before install: %d %q", code, body)
	}
	r.markInstalled()
	code, body = readyz(t, r)
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "not yet asserted") {
		t.Fatalf("installed, not asserted: %d %q", code, body)
	}
	r.markReady()
	r.markReady()
	if code, _ := readyz(t, r); code != http.StatusOK {
		t.Fatalf("ready: %d", code)
	}
	if !r.Ready() {
		t.Fatal("Ready() must report the latch")
	}
}

// The consumer-start hook runs only once the sealer is Ready, and exactly
// once (devdocs plan-2609-12 ruling D1 (a), slice 05 change 8).
func TestRunWhenReady_StartsOnlyWhenReady(t *testing.T) {
	r := NewDelegateKeyReadiness()
	var starts atomic.Int32
	done := r.RunWhenReady(context.Background(), func() { starts.Add(1) })

	r.markInstalled()
	time.Sleep(20 * time.Millisecond)
	if n := starts.Load(); n != 0 {
		t.Fatalf("started %d times with keys installed but not asserted, want 0", n)
	}

	r.markReady()
	r.markReady()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("start hook never ran after Ready")
	}
	if n := starts.Load(); n != 1 {
		t.Fatalf("started %d times, want 1", n)
	}
}

// Shutdown before Ready never starts consuming.
func TestRunWhenReady_CancelledNeverStarts(t *testing.T) {
	r := NewDelegateKeyReadiness()
	ctx, cancel := context.WithCancel(context.Background())
	var starts atomic.Int32
	done := r.RunWhenReady(ctx, func() { starts.Add(1) })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gate goroutine did not exit on cancel")
	}
	r.markReady()
	time.Sleep(10 * time.Millisecond)
	if n := starts.Load(); n != 0 {
		t.Fatalf("started %d times after cancel, want 0", n)
	}
}

func readyz(t *testing.T, r *DelegateKeyReadiness) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	r.ReadyzHandler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return rec.Code, rec.Body.String()
}
