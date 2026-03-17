package custodian

import (
	"encoding/json"
	"net/http"
)

// TokenRequest is the body for POST /api/token (log-owner token).
type TokenRequest struct {
	KeyOwnerID string `json:"key_owner_id"`
}

// handleToken implements POST /api/token — impersonate custody_signer.
func (a *API) handleToken(w http.ResponseWriter, r *http.Request) {
	if !a.RequireNormalApp(w, r) {
		return
	}
	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "invalid JSON")
		return
	}
	targetSA := a.cfg.CustodySignerSAEmail
	if targetSA == "" {
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "misconfigured", "CUSTODY_SIGNER_SA_EMAIL not set")
		return
	}
	tok, err := a.AcquireToken(r.Context(), targetSA)
	if err != nil {
		a.Logger.Error("failed to acquire custody token", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "token acquisition failed")
		return
	}
	a.writeJSON(w, http.StatusOK, tok)
	_ = req // key_owner_id can be used for audit; token works for all custody keys
}
