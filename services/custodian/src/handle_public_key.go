package custodian

import (
	"net/http"
	"strings"
)

// handleGetPublicKey implements GET /api/keys/{keyId}/public (no auth).
// Non-bootstrap keys: ResolveKeyName (short id or full resource name) + KMS GetPublicKey, same as sign.
func (a *API) handleGetPublicKey(w http.ResponseWriter, r *http.Request, keyID string) {
	if r.Method != http.MethodGet {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == BootstrapKeyAlias {
		a.handleBootstrapPublicKey(w, r)
		return
	}
	ctx := r.Context()
	cryptoKeyName, err := a.ResolveKeyName(keyID)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid key", err.Error())
		return
	}
	shortKey := keyIDFromName(cryptoKeyName)
	if e, ok := a.publicKeyCacheGet(shortKey); ok {
		a.writeCBOR(w, http.StatusOK, PublicKeyResponse{
			KeyID:     shortKey,
			PublicKey: e.PEM,
			Alg:       e.Alg,
		})
		return
	}
	pem, alg, err := kmsPublicKeyPEMAndAlg(ctx, cryptoKeyName)
	if err != nil {
		if kmsErrPublicKeyUnavailable(err) {
			a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "key not found")
			return
		}
		a.Logger.Error("kms public key", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "kms get public key failed")
		return
	}
	a.publicKeyCachePut(shortKey, pem, alg)
	a.writeCBOR(w, http.StatusOK, PublicKeyResponse{
		KeyID:     shortKey,
		PublicKey: pem,
		Alg:       alg,
	})
}

// handleBootstrapPublicKey serves GET /api/keys/:bootstrap/public from BOOTSTRAP_KMS_CRYPTO_KEY_ID
// (same KMS key as POST .../:bootstrap/sign). Not backed by the in-memory custody store.
func (a *API) handleBootstrapPublicKey(w http.ResponseWriter, r *http.Request) {
	cryptoKeyName := strings.TrimSpace(a.cfg.BootstrapKMSCryptoKeyID)
	if cryptoKeyName == "" {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank", "signing unavailable", "BOOTSTRAP_KMS_CRYPTO_KEY_ID not set")
		return
	}
	ctx := r.Context()
	pem, alg, err := kmsPublicKeyPEMAndAlg(ctx, cryptoKeyName)
	if err != nil {
		if kmsErrPublicKeyUnavailable(err) {
			a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "key not found")
			return
		}
		a.Logger.Error("kms public key (bootstrap)", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "kms get public key failed")
		return
	}
	a.writeCBOR(w, http.StatusOK, PublicKeyResponse{
		KeyID:     BootstrapKeyAlias,
		PublicKey: pem,
		Alg:       alg,
	})
}
