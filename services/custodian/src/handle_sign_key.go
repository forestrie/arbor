package custodian

import (
	"io"
	"net/http"
	"strings"
)

// BootstrapKeyAlias is the path segment that selects the configured bootstrap KMS key.
const BootstrapKeyAlias = ":bootstrap"

// handleSignKey implements POST /api/keys/{keyId}/sign — returns untagged COSE_Sign1.
func (a *API) handleSignKey(w http.ResponseWriter, r *http.Request, keyID string) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}

	keyID = strings.TrimSpace(keyID)
	if keyID == BootstrapKeyAlias {
		if !a.RequireBootstrapApp(w, r) {
			return
		}
	} else {
		if !a.RequireNormalApp(w, r) {
			return
		}
	}

	if !a.requireCBORContentType(w, r) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "could not read body")
		return
	}
	var req SignRequest
	if err := custodianCBORdm.Unmarshal(body, &req); err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "invalid CBOR")
		return
	}
	digest, err := DigestFromSignRequest(&req)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid request body", err.Error())
		return
	}

	var cryptoKeyName string
	if keyID == BootstrapKeyAlias {
		cryptoKeyName = strings.TrimSpace(a.cfg.BootstrapKMSCryptoKeyID)
		if cryptoKeyName == "" {
			a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank", "signing unavailable", "BOOTSTRAP_KMS_CRYPTO_KEY_ID not set")
			return
		}
	} else {
		var resolveErr error
		cryptoKeyName, resolveErr = a.ResolveKeyName(keyID)
		if resolveErr != nil {
			a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid key", resolveErr.Error())
			return
		}
	}

	ctx := r.Context()
	client, err := newKMSClient(ctx)
	if err != nil {
		a.Logger.Error("kms client for sign", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "kms client failed")
		return
	}
	defer client.Close()

	versionName, versionAlg, err := kmsResolveSigningVersion(ctx, client, cryptoKeyName)
	if err != nil {
		a.Logger.Error("kms resolve signing version", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "signing failed", "")
		return
	}

	sign1, err := BuildCustodianCOSESign1(ctx, client, versionName, versionAlg, digest)
	if err != nil {
		a.Logger.Error("build cose sign1", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "signing failed", "")
		return
	}

	a.writeCOSESign1(w, http.StatusOK, sign1)
}
