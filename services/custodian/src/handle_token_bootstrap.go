package custodian

import (
	"net/http"
)

// handleTokenBootstrap implements POST /api/token/bootstrap — impersonate delegation_signer.
func (a *API) handleTokenBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if !a.RequireBootstrapApp(w, r) {
		return
	}
	targetSA := a.cfg.DelegationSignerSAEmail
	if targetSA == "" {
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "misconfigured", "DELEGATION_SIGNER_SA_EMAIL not set")
		return
	}
	tok, err := a.AcquireToken(r.Context(), targetSA)
	if err != nil {
		a.Logger.Error("failed to acquire bootstrap token", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "token acquisition failed")
		return
	}
	a.writeJSON(w, http.StatusOK, tok)
}
