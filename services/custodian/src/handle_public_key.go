package custodian

import (
	"net/http"
)

// handleGetPublicKey implements GET /api/keys/{keyId}/public (no auth).
func (a *API) handleGetPublicKey(w http.ResponseWriter, r *http.Request, keyID string) {
	if r.Method != http.MethodGet {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	info, ok := a.store.GetByKeyID(keyID)
	if !ok {
		info, ok = a.store.Get(keyID)
	}
	if !ok {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "key not found")
		return
	}
	a.writeCBOR(w, http.StatusOK, PublicKeyResponse{
		KeyID:     info.KeyID,
		PublicKey: info.PublicKeyPEM,
		Alg:       info.Alg,
	})
}
