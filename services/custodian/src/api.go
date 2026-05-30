package custodian

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
)

// publicKeyCacheEntry caches PEM + alg after a successful KMS GetPublicKey (short crypto key id key).
type publicKeyCacheEntry struct {
	PEM string
	Alg string
}

// API provides the HTTP API for custodian.
type API struct {
	Logger         *slog.Logger
	cfg            Config
	store          *KeyStore
	logIDKeyCache  *logIDKeyLRU
	publicKeyMu    sync.RWMutex
	publicKeyCache map[string]publicKeyCacheEntry

	// listKeysOverride is a test-only seam. When set it replaces the real
	// GCP KMS list call in ResolveCustodianKeyIDForLogID; production never
	// sets this. The default (nil) routes through ListKeysWithLabels which
	// talks to the configured CUSTODY_KEY_RING_ID.
	listKeysOverride func(ctx context.Context, labels map[string]string, predicate string) ([]KeyListEntry, error)
}

// NewAPI builds an API with the given logger and config.
func NewAPI(logger *slog.Logger, cfg Config) *API {
	return &API{
		Logger:         logger,
		cfg:            cfg,
		store:          NewKeyStore(),
		logIDKeyCache:  newLogIDKeyLRU(cfg.LogIDCacheSize),
		publicKeyCache: make(map[string]publicKeyCacheEntry),
	}
}

func (a *API) publicKeyCacheGet(shortKey string) (publicKeyCacheEntry, bool) {
	a.publicKeyMu.RLock()
	defer a.publicKeyMu.RUnlock()
	if a.publicKeyCache == nil {
		return publicKeyCacheEntry{}, false
	}
	e, ok := a.publicKeyCache[shortKey]
	return e, ok
}

func (a *API) publicKeyCachePut(shortKey, pem, alg string) {
	a.publicKeyMu.Lock()
	defer a.publicKeyMu.Unlock()
	if a.publicKeyCache == nil {
		a.publicKeyCache = make(map[string]publicKeyCacheEntry)
	}
	a.publicKeyCache[shortKey] = publicKeyCacheEntry{PEM: pem, Alg: alg}
}

func (a *API) publicKeyCacheDelete(shortKey string) {
	a.publicKeyMu.Lock()
	defer a.publicKeyMu.Unlock()
	if a.publicKeyCache != nil {
		delete(a.publicKeyCache, shortKey)
	}
}

// RegisterRoutes wires the custodian API onto the provided mux.
//
// Endpoints:
//   - GET  /api/keys/{keyId}/public              (no auth); optional ?log-id=true;
//     {keyId} is the same as POST .../sign: short CryptoKey id under CUSTODY_KEY_RING_ID or full projects/.../cryptoKeys/... name
//   - POST /api/keys                             (normal app token) — create key
//   - GET  /api/keys/list / POST …/list          (normal app token) — list keys (labels)
//   - GET  /api/keys/curator/log-key              (normal app token) — ?logId=… → { keyId }
//   - POST /api/keys/{keyId}/delete              (bootstrap app token) — destroy all key versions
//   - POST /api/keys/{keyId}/versions/delete-from (bootstrap app token) — destroy versions <= N
//   - POST /api/delegations                  (APP_TOKEN) — issue delegation lease (local custody)
//   - POST /api/keys/{keyId}/sign                (APP_TOKEN; BOOTSTRAP_APP_TOKEN if keyId is :bootstrap);
//     optional SignRequest.rawSignatureOnly → CBOR { signature } (r‖s), not COSE Sign1; optional ?log-id=true
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/delegations", a.handleDelegations)
	mux.HandleFunc("/api/keys/list", a.handleListKeys)
	mux.HandleFunc("/api/keys/curator/log-key", a.handleCuratorLogKey)
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
	var resolveErr error
	keyID, resolveErr = a.resolveKeyPathSegment(r, keyID)
	if resolveErr != nil {
		st := http.StatusBadRequest
		title := "bad request"
		if errors.Is(resolveErr, ErrNoCustodianKeyForLogID) {
			st = http.StatusNotFound
			title = "not found"
		}
		a.writeProblem(w, r, st, "about:blank", title, resolveErr.Error())
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
