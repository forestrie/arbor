package signer

import (
	"log/slog"
	"net/http"
)

// API provides the HTTP API for the signer (Plan 0004 subplan 04).
// Delegation for bootstrap and for parent log; no private key material is returned.
type API struct {
	Logger         *slog.Logger
	KeySigner      KeySigner
	BootstrapKeyID string
	ParentResolver *ParentResolver
}

// RegisterRoutes wires the delegation endpoints onto the provided mux.
//
//	POST /delegate/bootstrap — delegation for local (bootstrap) key; body: payload_hash or payload
//	POST /delegate/parent    — delegation for parent log; body: parent_log_id, payload_hash or payload
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/delegate/bootstrap", a.handleDelegateBootstrap)
	mux.HandleFunc("/delegate/parent", a.handleDelegateParent)
}
