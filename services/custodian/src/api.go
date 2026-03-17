package custodian

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// API provides the HTTP API for custodian.
type API struct {
	Logger *slog.Logger
	cfg    Config
	store  *KeyStore
}

// NewAPI builds an API with the given logger and config.
func NewAPI(logger *slog.Logger, cfg Config) *API {
	return &API{
		Logger: logger,
		cfg:   cfg,
		store: NewKeyStore(),
	}
}

// RegisterRoutes wires the custodian API onto the provided mux.
//
// Endpoints:
//   - GET  /api/keys/{keyId}/public  (no auth)
//   - POST /api/keys                 (normal app token) — create key
//   - POST /api/token                (normal app token) — log-owner token
//   - POST /api/token/bootstrap      (bootstrap app token) — bootstrap token
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/keys", a.routeKeysCreate)
	mux.HandleFunc("/api/keys/", a.routeKeys)
	mux.HandleFunc("/api/token", a.routeToken)
	mux.HandleFunc("/api/token/", a.routeTokenWithPath)
}

// routeKeysCreate: POST /api/keys (exact match).
func (a *API) routeKeysCreate(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/keys" {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
		return
	}
	a.handleCreateKey(w, r)
}

// routeKeys: /api/keys/ or /api/keys/{keyId}/public
func (a *API) routeKeys(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	if path == "" {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
		return
	}
	parts := strings.SplitN(path, "/", 2)
	keyID := parts[0]
	if keyID == "" {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
		return
	}
	if len(parts) == 2 && parts[1] == "public" {
		a.handleGetPublicKey(w, r, keyID)
		return
	}
	a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
}

// routeToken: POST /api/token (body: key_owner_id for log-owner token)
func (a *API) routeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	a.handleToken(w, r)
}

// routeTokenWithPath: POST /api/token/bootstrap
func (a *API) routeTokenWithPath(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/token/")
	if path == "bootstrap" {
		a.handleTokenBootstrap(w, r)
		return
	}
	a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
}

// writeJSON sends a JSON response with status code.
func (a *API) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
