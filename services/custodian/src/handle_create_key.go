package custodian

import (
	"encoding/json"
	"net/http"
)

// CreateKeyRequest is the body for POST /api/keys.
type CreateKeyRequest struct {
	KeyOwnerID string `json:"key_owner_id"`
	Alg        string `json:"alg,omitempty"` // ES256 or KS256
}

// CreateKeyResponse is the response for POST /api/keys.
type CreateKeyResponse struct {
	KeyID      string `json:"key_id"`
	PublicKey  string `json:"public_key,omitempty"`
	Alg        string `json:"alg,omitempty"`
}

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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "invalid JSON")
		return
	}
	if req.KeyOwnerID == "" {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "key_owner_id required")
		return
	}
	// Idempotent: if we already have a key for this owner, return it.
	if info, ok := a.store.Get(req.KeyOwnerID); ok {
		a.writeJSON(w, http.StatusOK, CreateKeyResponse{
			KeyID:     info.KeyID,
			PublicKey: info.PublicKeyPEM,
			Alg:       info.Alg,
		})
		return
	}
	keyName, publicKeyPEM, err := a.CreateKeyForOwner(r.Context(), req.KeyOwnerID, req.Alg)
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
	a.writeJSON(w, http.StatusCreated, CreateKeyResponse{
		KeyID:     keyName,
		PublicKey: publicKeyPEM,
		Alg:       alg,
	})
}
