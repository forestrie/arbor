package custodian

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// TestHandleDelegations_proxiesOnKeyNotFound drives the only routing path:
// local KMS returns ErrNoCustodianKeyForLogID, the coordinator is
// configured, so the request proxies to coordinator POST /api/delegations.
// Asserts no signing-route probe is attempted (stage 1 is gone).
func TestHandleDelegations_proxiesOnKeyNotFound(t *testing.T) {
	logBytes := logIDBytes16(t)
	var coordinatorIssue bool
	coord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/signing-route") {
			t.Fatalf("unexpected signing-route probe: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/delegations" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		coordinatorIssue = true
		resp := delegationcert.DelegationIssueResponse{
			IssuedAt:    1,
			ExpiresAt:   999,
			Certificate: []byte{0x01},
		}
		b, _ := custodianCBORem.Marshal(resp)
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer coord.Close()

	logger, _ := NewLogger(0)
	api := NewAPI(logger, Config{
		AppToken:                 "app-token",
		DelegationCoordinatorURL: coord.URL,
	})
	api.listKeysOverride = func(ctx context.Context, labels map[string]string, predicate string) ([]KeyListEntry, error) {
		return nil, nil
	}

	body, _ := custodianCBORem.Marshal(delegationcert.DelegationIssueRequest{
		LogID:              logBytes,
		DelegatedPublicKey: []byte{1},
		Algorithm:          "ES256",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/delegations", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("Authorization", "Bearer app-token")
	rec := httptest.NewRecorder()

	api.handleDelegations(rec, req)

	if !coordinatorIssue {
		t.Fatal("expected coordinator issue call when local KMS has no key")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out delegationcert.DelegationIssueResponse
	if err := custodianCBORdm.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Certificate) != 1 {
		t.Fatalf("cert=%v", out.Certificate)
	}
}

// TestHandleDelegations_404WhenNoLocalKeyAndNoCoordinator covers the hard
// error path: local KMS has no key AND no coordinator URL is configured.
// Custodian must return 404 with the not-found problem detail. No silent
// fallback to anything else.
func TestHandleDelegations_404WhenNoLocalKeyAndNoCoordinator(t *testing.T) {
	logBytes := logIDBytes16(t)

	logger, _ := NewLogger(0)
	api := NewAPI(logger, Config{
		AppToken: "app-token",
		// DelegationCoordinatorURL deliberately unset.
	})
	api.listKeysOverride = func(ctx context.Context, labels map[string]string, predicate string) ([]KeyListEntry, error) {
		return nil, nil
	}

	body, _ := custodianCBORem.Marshal(delegationcert.DelegationIssueRequest{
		LogID:              logBytes,
		DelegatedPublicKey: []byte{1},
		Algorithm:          "ES256",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/delegations", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("Authorization", "Bearer app-token")
	rec := httptest.NewRecorder()

	api.handleDelegations(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "not found") {
		t.Fatalf("expected not-found problem detail; got %s", rec.Body.String())
	}
}

func TestProxyDelegationIssue_forwardsCBOR(t *testing.T) {
	coord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/delegations" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		var req delegationcert.DelegationIssueRequest
		if err := custodianCBORdm.Unmarshal(body, &req); err != nil {
			t.Fatal(err)
		}
		resp := delegationcert.DelegationIssueResponse{Certificate: []byte{0xab}}
		b, _ := custodianCBORem.Marshal(resp)
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(b)
	}))
	defer coord.Close()

	logger, _ := NewLogger(0)
	api := NewAPI(logger, Config{
		AppToken:                 "tok",
		DelegationCoordinatorURL: coord.URL,
	})

	in, _ := custodianCBORem.Marshal(delegationcert.DelegationIssueRequest{
		LogID: logIDBytes16(t),
	})
	out, st, err := api.proxyDelegationIssue(t.Context(), in, "Bearer tok")
	if err != nil || st != http.StatusOK {
		t.Fatalf("err=%v st=%d", err, st)
	}
	if len(out.Certificate) != 1 || out.Certificate[0] != 0xab {
		t.Fatalf("cert=%v", out.Certificate)
	}
}

func logIDBytes16(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, 16)
	for i := range raw {
		raw[i] = byte(i)
	}
	if _, err := logIDHexFromWire(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}
