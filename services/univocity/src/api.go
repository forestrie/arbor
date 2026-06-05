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
}
