package custodian

import (
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
		cfg:    cfg,
		store:  NewKeyStore(),
	}
}

// RegisterRoutes wires the custodian API onto the provided mux.
//
// Endpoints:
//   - GET  /api/keys/{keyId}/public              (no auth)
//   - POST /api/keys                             (normal app token) — create key
//   - POST /api/keys/list                        (normal app token) — list keys matching labels (predicate and/or)
//   - POST /api/keys/{keyId}/delete              (bootstrap app token) — destroy all key versions
//   - POST /api/keys/{keyId}/versions/delete-from (bootstrap app token) — destroy versions <= N
//   - POST /api/keys/{keyId}/sign                (APP_TOKEN; BOOTSTRAP_APP_TOKEN if keyId is :bootstrap)
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/keys/list", a.handleListKeys)
	mux.HandleFunc("/api/keys", a.routeKeysCreate)
	mux.HandleFunc("/api/keys/", a.routeKeys)
}

// routeKeysCreate: POST /api/keys (exact match).
func (a *API) routeKeysCreate(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/keys" {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
		return
	}
	a.handleCreateKey(w, r)
}

// routeKeys: /api/keys/{keyId}/public | .../delete | .../versions/delete-from | .../sign
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
	if len(parts) == 2 {
		rest := parts[1]
		if rest == "public" {
			a.handleGetPublicKey(w, r, keyID)
			return
		}
		if rest == "delete" {
			a.handleDeleteKey(w, r, keyID)
			return
		}
		if rest == "versions/delete-from" {
			a.handleDeleteKeyVersionsFrom(w, r, keyID)
			return
		}
		if rest == "sign" {
			a.handleSignKey(w, r, keyID)
			return
		}
	}
	a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
}
