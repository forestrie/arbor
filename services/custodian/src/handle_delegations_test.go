package custodian

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

func TestRegisterRoutes_Delegations_Unauthorized(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(delegationcert.DelegationIssueRequest{
		LogID:              make([]byte, 16),
		DelegatedPublicKey: []byte{0x01},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/delegations", bytes.NewReader(body))
	req.Header.Set("Content-Type", cborContentType)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}
}

func TestRegisterRoutes_Delegations_MethodNotAllowed(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/delegations", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestLogIDHexFromWire(t *testing.T) {
	raw := make([]byte, 16)
	for i := range raw {
		raw[i] = byte(i)
	}
	got, err := logIDHexFromWire(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("expected 32 hex chars, got %q", got)
	}
}
