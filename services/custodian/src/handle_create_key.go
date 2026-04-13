package custodian

import (
	"errors"
	"net/http"
	"strings"
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
	if strings.TrimSpace(req.KeyOwnerID) == "" {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "keyOwnerId required")
		return
	}
	normOwner, err := NormalizeForestrieHexID32(req.KeyOwnerID)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "invalid keyOwnerId")
		return
	}
	if strings.TrimSpace(req.SelfLogID) == "" {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "selfLogId required")
		return
	}
	normSelf, err := NormalizeForestrieHexID32(req.SelfLogID)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "invalid selfLogId")
		return
	}
	cryptoKeyShort := normSelf
	if info, ok := a.store.Get(normOwner); ok {
		if keyIDFromName(info.KeyID) != cryptoKeyShort {
			a.writeProblem(w, r, http.StatusConflict, "about:blank", "conflict", "keyOwnerId already has a key for a different selfLogId")
			return
		}
		a.publicKeyCachePut(keyIDFromName(info.KeyID), info.PublicKeyPEM, info.Alg)
		a.writeCBOR(w, http.StatusOK, CreateKeyResponse{
			KeyID:     info.KeyID,
			PublicKey: info.PublicKeyPEM,
			Alg:       info.Alg,
		})
		return
	}
	keyName, publicKeyPEM, err := a.CreateKeyForOwner(r.Context(), normOwner, normSelf, req.Alg, req.ProtectionLevel, req.Labels)
	if err != nil {
		if errors.Is(err, ErrForbiddenUserLabelKey) {
			a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "user label key uses reserved Forestrie operator prefix")
			return
		}
		a.Logger.Error("failed to create key", "key_owner_id", normOwner, "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "key creation failed")
		return
	}
	alg := req.Alg
	if alg == "" {
		alg = "ES256"
	}
	a.store.Set(normOwner, KeyInfo{
		KeyID:        keyName,
		PublicKeyPEM: publicKeyPEM,
		Alg:          alg,
	})
	a.publicKeyCachePut(keyIDFromName(keyName), publicKeyPEM, alg)
	a.writeCBOR(w, http.StatusCreated, CreateKeyResponse{
		KeyID:     keyName,
		PublicKey: publicKeyPEM,
		Alg:       alg,
	})
}
