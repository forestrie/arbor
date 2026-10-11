package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/forestrie/arbor/services/sealer"
)

// TestReadyz pins /readyz to the standing delegate key state (plan-2609-12
// slice 05): 503 before the first load hands over a readiness handle, 503
// while keys are unloaded or unregistered, 200 once ready.
func TestReadyz(t *testing.T) {
	var dk atomic.Pointer[sealer.DelegateKeyReadiness]
	mux := http.NewServeMux()
	setupHealthChecks(mux, &dk)

	get := func() int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec.Code
	}

	if code := get(); code != http.StatusServiceUnavailable {
		t.Fatalf("starting: %d, want 503", code)
	}
	dk.Store(&sealer.DelegateKeyReadiness{})
	if code := get(); code != http.StatusServiceUnavailable {
		t.Fatalf("keys not loaded: %d, want 503", code)
	}
	// DELEGATE_KEY_EPOCH=0 yields an always-ready handle.
	dk.Store(sealer.StartDelegateKeysWithRetry(t.Context(), nil, mustLogger(t), sealer.Config{}, nil, nil))
	if code := get(); code != http.StatusOK {
		t.Fatalf("disabled: %d, want 200", code)
	}
}

func mustLogger(t *testing.T) *slog.Logger {
	t.Helper()
	logger, _ := sealer.NewLogger(0)
	return logger
}
