package custodian

import (
	"io"
	"net/http"
	"strings"
)

// handleSignKey implements POST /api/keys/{keyId}/sign — returns untagged COSE_Sign1.
func (a *API) handleSignKey(w http.ResponseWriter, r *http.Request, keyID string) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}

	if !a.RequireNormalApp(w, r) {
		return
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

	keyID = strings.TrimSpace(keyID)
	cryptoKeyName, resolveErr := a.ResolveKeyName(keyID)
	if resolveErr != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid key", resolveErr.Error())
		return
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

	if req.RawSignatureOnly {
		const coordWidth = 32
		der, err := kmsAsymmetricSignSHA256(ctx, client, versionName, digest)
		if err != nil {
			a.Logger.Error("kms raw sign", "error", err)
			a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "signing failed", "")
			return
		}
		rawSig, err := ecdsaDERSignatureToIEEE1363(der, coordWidth)
		if err != nil {
			a.Logger.Error("der to ieee p1363", "error", err)
			a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "signing failed", "")
			return
		}
		a.writeCBOR(w, http.StatusOK, RawSignResponse{Signature: rawSig})
		return
	}

	sign1, err := BuildCustodianCOSESign1(ctx, client, versionName, versionAlg, digest, a.Logger, keyID)
	if err != nil {
		a.Logger.Error("build cose sign1", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "signing failed", "")
		return
	}

	a.writeCOSESign1(w, http.StatusOK, sign1)
}
