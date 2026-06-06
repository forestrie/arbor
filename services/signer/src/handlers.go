package signer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// DelegateBootstrapRequest is the body for POST /delegate/bootstrap (Plan 0004 subplan 04 §6.1).
type DelegateBootstrapRequest struct {
	// PayloadHash is the 32-byte digest as hex (64 chars). Exactly one of PayloadHash or Payload.
	PayloadHash string `json:"payload_hash,omitempty"`
	// Payload is the raw bytes as base64. Signer will SHA-256 it to get digest.
	Payload string `json:"payload,omitempty"`
}

// DelegateParentRequest is the body for POST /delegate/parent (§6.3).
type DelegateParentRequest struct {
	ParentLogID string `json:"parent_log_id"` // canonical dashed UUID
	PayloadHash string `json:"payload_hash,omitempty"`
	Payload     string `json:"payload,omitempty"`
}

// DelegateResponse is the JSON response for both delegate endpoints (§6.1, §6.3).
type DelegateResponse struct {
	Signature string `json:"signature"` // ECDSA signature as hex (r||s or DER; KMS returns raw r||s for EC)
}

func (a *API) handleDelegateBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if a.KeySigner == nil || a.BootstrapKeyID == "" {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank", "bootstrap delegation unavailable", "SIGNER_BOOTSTRAP_KEY_ID not configured")
		return
	}

	var req DelegateBootstrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid request body", err.Error())
		return
	}
	digest, err := a.digestFromRequest(req.PayloadHash, req.Payload)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid payload or payload_hash", err.Error())
		return
	}

	signature, err := a.KeySigner.Sign(r.Context(), a.BootstrapKeyID, digest)
	if err != nil {
		a.Logger.Error("bootstrap sign failed", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "signing failed", "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(DelegateResponse{
		Signature: toHex(signature),
	})
}

func (a *API) handleDelegateParent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if a.KeySigner == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank", "delegation unavailable", "signer not configured")
		return
	}

	var req DelegateParentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid request body", err.Error())
		return
	}
	req.ParentLogID = strings.TrimSpace(req.ParentLogID)
	if req.ParentLogID == "" {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "parent_log_id required", "")
		return
	}

	keyID, err := a.ParentResolver.ResolveKeyID(r.Context(), req.ParentLogID)
	if err != nil {
		a.Logger.Debug("parent key resolve failed", "parent_log_id", req.ParentLogID, "error", err)
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "parent log key not found", err.Error())
		return
	}

	digest, err := a.digestFromRequest(req.PayloadHash, req.Payload)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid payload or payload_hash", err.Error())
		return
	}

	signature, err := a.KeySigner.Sign(r.Context(), keyID, digest)
	if err != nil {
		a.Logger.Error("parent sign failed", "parent_log_id", req.ParentLogID, "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "signing failed", "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(DelegateResponse{
		Signature: toHex(signature),
	})
}

func (a *API) digestFromRequest(payloadHash, payload string) ([]byte, error) {
	payloadHash = strings.TrimSpace(payloadHash)
	payload = strings.TrimSpace(payload)
	if payloadHash != "" && payload != "" {
		return nil, fmt.Errorf("provide exactly one of payload_hash or payload")
	}
	if payloadHash != "" {
		return DigestFromPayloadHash(payloadHash)
	}
	if payload != "" {
		raw, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return nil, err
		}
		return DigestFromPayload(raw), nil
	}
	return nil, fmt.Errorf("provide payload_hash or payload")
}

func toHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}
