package univocity

import (
	"log/slog"
	"net/http"
	"strings"
)

// API provides the HTTP API for the univocity auth-log status service.
type API struct {
	Logger *slog.Logger
	Chain  *UnivocityContract
}

// RegisterRoutes wires the API endpoints onto the provided mux.
//
//	GET /api/root              — root exists and rootLogId
//	GET /api/logs              — list known auth logs (at least root)
//	GET /api/logs/{logId}/config      — log kind and config
//	GET /api/logs/{logId}/signing-key — sealer key resolution
func (a API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/root", a.handleRoot)
	mux.HandleFunc("/api/logs", a.handleLogsList)
	mux.HandleFunc("/api/logs/", a.routeHandler)
}

func (a API) routeHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if strings.HasSuffix(path, "/config") {
		a.handleLogConfig(w, r)
		return
	}
	if strings.HasSuffix(path, "/signing-key") {
		a.handleSigningKey(w, r)
		return
	}
	a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
}
