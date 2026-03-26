package custodian

import (
	"net/http"
	"strings"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

// handleGetPublicKey implements GET /api/keys/{keyId}/public (no auth).
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

// handleBootstrapPublicKey serves GET /api/keys/:bootstrap/public from BOOTSTRAP_KMS_CRYPTO_KEY_ID
// (same KMS key as POST .../:bootstrap/sign). Not backed by the in-memory custody store.
func (a *API) handleBootstrapPublicKey(w http.ResponseWriter, r *http.Request) {
	cryptoKeyName := strings.TrimSpace(a.cfg.BootstrapKMSCryptoKeyID)
	if cryptoKeyName == "" {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank", "signing unavailable", "BOOTSTRAP_KMS_CRYPTO_KEY_ID not set")
		return
	}
	ctx := r.Context()
	client, err := newKMSClient(ctx)
	if err != nil {
		a.Logger.Error("kms client for public key", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "kms client failed")
		return
	}
	defer client.Close()

	versionName, versionAlg, err := kmsResolveSigningVersion(ctx, client, cryptoKeyName)
	if err != nil {
		a.Logger.Error("kms resolve signing version", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "kms resolve failed")
		return
	}
	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
	if err != nil {
		a.Logger.Error("kms get public key", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "kms get public key failed")
		return
	}
	algStr, err := kmsPublicKeyAlgString(versionAlg)
	if err != nil {
		a.Logger.Error("unsupported kms algorithm for public key", "alg", versionAlg, "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "unsupported algorithm")
		return
	}
	a.writeCBOR(w, http.StatusOK, PublicKeyResponse{
		KeyID:     BootstrapKeyAlias,
		PublicKey: pubResp.GetPem(),
		Alg:       algStr,
	})
}
