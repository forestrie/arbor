package custodian

import (
	"net/http"
)

// handleCreateKey implements POST /api/keys — create a key for a log owner.
func (a *API) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if !a.RequireNormalApp(w, r) {
		return
	}
	var req CreateKeyRequest
	if !a.readCBORBody(w, r, &req) {
		return
	}
	if req.KeyOwnerID == "" {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "keyOwnerId required")
		return
	}
	cryptoKeyShort, uuidOK := cryptoKeyShortIDFromLogUUID(req.SelfLogID)
	if !uuidOK {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "selfLogId must be a valid UUID")
		return
	}
	if info, ok := a.store.Get(req.KeyOwnerID); ok {
		if keyIDFromName(info.KeyID) != cryptoKeyShort {
			a.writeProblem(w, r, http.StatusConflict, "about:blank", "conflict", "keyOwnerId already has a key for a different selfLogId")
			return
		}
		a.writeCBOR(w, http.StatusOK, CreateKeyResponse{
			KeyID:     info.KeyID,
			PublicKey: info.PublicKeyPEM,
			Alg:       info.Alg,
		})
		return
	}
	keyName, publicKeyPEM, err := a.CreateKeyForOwner(r.Context(), req.KeyOwnerID, req.SelfLogID, req.Alg, req.Labels)
	if err != nil {
		a.Logger.Error("failed to create key", "key_owner_id", req.KeyOwnerID, "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "key creation failed")
		return
	}
	alg := req.Alg
	if alg == "" {
		alg = "ES256"
	}
	a.store.Set(req.KeyOwnerID, KeyInfo{
		KeyID:        keyName,
		PublicKeyPEM: publicKeyPEM,
		Alg:          alg,
	})
	a.writeCBOR(w, http.StatusCreated, CreateKeyResponse{
		KeyID:     keyName,
		PublicKey: publicKeyPEM,
		Alg:       alg,
	})
}
