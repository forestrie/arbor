package custodian

import (
	"errors"
	"net/http"
	"strings"
)

// handleEnsureKey implements POST /api/keys — ensure a custody key for a log (idempotent).
func (a *API) handleEnsureKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if !a.RequireNormalApp(w, r) {
		return
	}
	var req EnsureKeyRequest
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
	alg := req.Alg
	if alg == "" {
		alg = "ES256"
	}
	if info, ok := a.store.Get(normSelf); ok {
		a.publicKeyCachePut(keyIDFromName(info.KeyID), info.PublicKeyPEM, info.Alg)
		a.writeCBOR(w, http.StatusOK, EnsureKeyResponse{
			KeyID:     info.KeyID,
			PublicKey: info.PublicKeyPEM,
			Alg:       info.Alg,
			Created:   false,
		})
		return
	}

	var keyName, publicKeyPEM string
	var created bool
	if a.ensureKeyOverride != nil {
		keyName, publicKeyPEM, created, err = a.ensureKeyOverride(r.Context(), normOwner, normSelf, req.Alg, req.ProtectionLevel, req.Labels)
	} else {
		keyName, publicKeyPEM, created, err = a.EnsureKeyForOwner(r.Context(), normOwner, normSelf, req.Alg, req.ProtectionLevel, req.Labels)
	}
	if err != nil {
		if errors.Is(err, ErrForbiddenUserLabelKey) {
			a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "user label key uses reserved Forestrie operator prefix")
			return
		}
		a.Logger.Error("failed to ensure key", "self_log_id", normSelf, "key_owner_id", normOwner, "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "key ensure failed")
		return
	}
	a.store.Set(normSelf, KeyInfo{
		KeyID:        keyName,
		PublicKeyPEM: publicKeyPEM,
		Alg:          alg,
	})
	a.publicKeyCachePut(keyIDFromName(keyName), publicKeyPEM, alg)
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	a.writeCBOR(w, status, EnsureKeyResponse{
		KeyID:     keyName,
		PublicKey: publicKeyPEM,
		Alg:       alg,
		Created:   created,
	})
}
