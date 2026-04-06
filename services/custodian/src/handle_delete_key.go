package custodian

import (
	"net/http"
)

// handleDeleteKey implements POST /api/keys/{keyId}/delete — schedule destruction of all key versions.
// Bootstrap app token required.
func (a *API) handleDeleteKey(w http.ResponseWriter, r *http.Request, keyID string) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if !a.RequireBootstrapApp(w, r) {
		return
	}
	keyName, err := a.ResolveKeyName(keyID)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", err.Error())
		return
	}
	count, err := a.DestroyKey(r.Context(), keyName)
	if err != nil {
		a.Logger.Error("failed to destroy key", "key_id", keyID, "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "key destruction failed")
		return
	}
	a.publicKeyCacheDelete(keyIDFromName(keyName))
	a.writeCBOR(w, http.StatusOK, DeleteKeyResponse{
		KeyID:          keyName,
		DestroyedCount: count,
	})
}

// handleDeleteKeyVersionsFrom implements POST /api/keys/{keyId}/versions/delete-from — schedule destruction of versions <= N.
// Bootstrap app token required.
func (a *API) handleDeleteKeyVersionsFrom(w http.ResponseWriter, r *http.Request, keyID string) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if !a.RequireBootstrapApp(w, r) {
		return
	}
	var req DeleteKeyVersionsFromRequest
	if !a.readCBORBody(w, r, &req) {
		return
	}
	if req.Version < 1 {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "version must be >= 1")
		return
	}
	keyName, err := a.ResolveKeyName(keyID)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", err.Error())
		return
	}
	count, err := a.DestroyKeyVersionsFrom(r.Context(), keyName, req.Version)
	if err != nil {
		a.Logger.Error("failed to destroy key versions", "key_id", keyID, "version", req.Version, "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "version destruction failed")
		return
	}
	a.writeCBOR(w, http.StatusOK, DeleteKeyResponse{
		KeyID:          keyName,
		DestroyedCount: count,
	})
}
