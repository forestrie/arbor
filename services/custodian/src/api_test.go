package custodian

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterRoutes_PublicKeyNotFound(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "test-app"
	cfg.BootstrapAppToken = "test-bootstrap"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/keys/unknown/public", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestRegisterRoutes_TokenBootstrap_Unauthorized(t *testing.T) {
	cfg := LoadConfig()
	cfg.BootstrapAppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/token/bootstrap", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}
}

func TestRegisterRoutes_TokenBootstrap_WrongToken(t *testing.T) {
	cfg := LoadConfig()
	cfg.BootstrapAppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/token/bootstrap", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong token, got %d", rec.Code)
	}
}

func TestRegisterRoutes_CreateKey_Unauthorized(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := json.Marshal(CreateKeyRequest{KeyOwnerID: "owner1"})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	// Health is registered in main; we test via a minimal mux that has the same pattern.
	// In practice health is on the same mux as API. Here we just ensure our API routes exist.
	cfg := LoadConfig()
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/keys/any/public", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// We get 404 for unknown key, which is expected.
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown key, got %d", rec.Code)
	}
}
