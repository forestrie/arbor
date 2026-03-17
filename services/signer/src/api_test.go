package signer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockKeySigner returns a fixed signature for tests (Plan 0004 subplan 04 §6.2, §6.4 verification).
type mockKeySigner struct {
	signature []byte
}

func (m *mockKeySigner) Sign(ctx context.Context, keyID string, digest []byte) ([]byte, error) {
	if m.signature != nil {
		return m.signature, nil
	}
	return []byte("mock_signature_32_bytes_long!!!!!"), nil
}

func TestHandleDelegateBootstrap_Success(t *testing.T) {
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}
	api := &API{
		Logger:         mustLogger(t),
		KeySigner:      &mockKeySigner{signature: sig},
		BootstrapKeyID: "projects/p/locations/l/keyRings/r/cryptoKeys/k",
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	digest := make([]byte, 32)
	digest[0] = 1
	body, _ := json.Marshal(DelegateBootstrapRequest{PayloadHash: hex.EncodeToString(digest)})
	req := httptest.NewRequest(http.MethodPost, "/delegate/bootstrap", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp DelegateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	got, err := hex.DecodeString(resp.Signature)
	if err != nil || len(got) != 64 {
		t.Errorf("expected 64-byte hex signature, got %q", resp.Signature)
	}
}

func TestHandleDelegateBootstrap_NoBootstrapKey_503(t *testing.T) {
	api := &API{
		Logger:         mustLogger(t),
		KeySigner:      &mockKeySigner{},
		BootstrapKeyID: "",
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := json.Marshal(DelegateBootstrapRequest{PayloadHash: hex.EncodeToString(make([]byte, 32))})
	req := httptest.NewRequest(http.MethodPost, "/delegate/bootstrap", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when bootstrap key not configured, got %d", rec.Code)
	}
}

func TestHandleDelegateParent_ResolvesToBootstrap(t *testing.T) {
	// When parent is root and resolver returns bootstrap key, sign succeeds.
	sig := []byte("parent_sig_32_bytes!!!!!!!!!!!!!!!!!")
	resolver := &ParentResolver{
		BootstrapKeyID: "projects/p/locations/l/keyRings/r/cryptoKeys/bootstrap",
		RootLogIDHex:   "0x0000000000000000000000000000000000000000000000000000000000000001",
	}
	api := &API{
		Logger:         mustLogger(t),
		KeySigner:      &mockKeySigner{signature: sig},
		BootstrapKeyID: "projects/p/locations/l/keyRings/r/cryptoKeys/bootstrap",
		ParentResolver: resolver,
	}
	// Simulate that parent 0x00...01 is the root (so resolver returns bootstrap key).
	resolver.ParentKeys = map[string]string{
		"0000000000000000000000000000000000000000000000000000000000000001": "projects/p/locations/l/keyRings/r/cryptoKeys/bootstrap",
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := json.Marshal(DelegateParentRequest{
		ParentLogID: "0x0000000000000000000000000000000000000000000000000000000000000001",
		PayloadHash: hex.EncodeToString(make([]byte, 32)),
	})
	req := httptest.NewRequest(http.MethodPost, "/delegate/parent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp DelegateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Signature != hex.EncodeToString(sig) {
		t.Errorf("signature mismatch")
	}
}

func TestHandleDelegateParent_UnknownParent_404(t *testing.T) {
	resolver := &ParentResolver{
		BootstrapKeyID: "projects/p/kms/bootstrap",
		ParentKeys:     map[string]string{}, // no mapping for any parent
	}
	api := &API{
		Logger:         mustLogger(t),
		KeySigner:      &mockKeySigner{},
		ParentResolver: resolver,
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := json.Marshal(DelegateParentRequest{
		ParentLogID: "0x0000000000000000000000000000000000000000000000000000000000000099",
		PayloadHash: hex.EncodeToString(make([]byte, 32)),
	})
	req := httptest.NewRequest(http.MethodPost, "/delegate/parent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown parent, got %d", rec.Code)
	}
}

func mustLogger(t *testing.T) *slog.Logger {
	t.Helper()
	logger, _ := NewLogger(slog.LevelError)
	return logger
}
