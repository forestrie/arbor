package univocity

import (
	"log/slog"
	"net/http"
)

// API provides the HTTP API for the univocity trust-root service.
type API struct {
	Logger   *slog.Logger
	Pool     ChainResolver
	Resolver *ForestResolver

	// Store is the univocity-owned genesis + grant + index store. When nil the
	// write/authorize endpoints are unavailable.
	Store Store
	// APIToken authenticates canopy->univocity write/authorize calls. When empty
	// those endpoints return 503 (disabled).
	APIToken string
	// AdminToken authenticates destructive admin endpoints (delete). When empty
	// the admin endpoints are disabled.
	AdminToken string
	// AllowUnanchoredGenesis permits storing genesis/grants when the on-chain
	// bootstrap anchor cannot be reached (local/dev/e2e against a stack with no
	// deployed contract). Never enable in production.
	AllowUnanchoredGenesis bool

	// Bootstrap caches per-(chainId,contract) on-chain bootstrap keys.
	Bootstrap *bootstrapCache
}

// RegisterRoutes wires scoped and logId-only endpoints onto the mux.
func (a API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/{chainId}/{contract}/root", a.handleScopedRoot)
	mux.HandleFunc("GET /api/{chainId}/{contract}/logs", a.handleScopedLogsList)
	mux.HandleFunc(
		"GET /api/{chainId}/{contract}/logs/{logId}/config",
		a.handleScopedLogConfig,
	)
	mux.HandleFunc(
		"GET /api/{chainId}/{contract}/logs/{logId}/public-root",
		a.handleScopedPublicRoot,
	)

	mux.HandleFunc("GET /api/logs/{logId}/root", a.handleLogIDRoot)
	mux.HandleFunc("GET /api/logs/{logId}/public-root", a.handleLogIDPublicRoot)

	// Owned store: genesis, grants, authorize (token-auth).
	mux.HandleFunc("POST /api/forest/{logId}/genesis", a.handlePostGenesis)
	mux.HandleFunc("GET /api/forest/{logId}/genesis", a.handleGetGenesis)
	mux.HandleFunc("POST /api/grants", a.handlePostGrant)
	mux.HandleFunc("POST /api/authorize", a.handleAuthorize)

	// Admin (admin-token): explicit, no automatic GC.
	mux.HandleFunc("DELETE /api/forest/{logId}/grants/{subject}", a.handleDeleteGrant)
	mux.HandleFunc("DELETE /api/forest/{logId}", a.handleDeleteForest)
}
