package univocity

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleRoot_UnavailableWhenChainNotConfigured(t *testing.T) {
	logger, _ := NewLogger(0)
	api := API{Logger: logger, Chain: nil}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/root", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 503 when chain not configured, got %d, body=%s", resp.StatusCode, string(body))
	}
}
