package custodian

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterRoutes_PublicKey_InvalidKeyWhenRingUnset(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "test-app"
	cfg.BootstrapAppToken = "test-bootstrap"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/keys/unknown/public", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when CUSTODY_KEY_RING_ID unset, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != problemCBORType {
		t.Errorf("expected problem+cbor, got %q", ct)
	}
	var pd ProblemDetail
	if err := custodianCBORdm.Unmarshal(rec.Body.Bytes(), &pd); err != nil {
		t.Fatalf("problem body: %v", err)
	}
	if pd.Title != "invalid key" {
		t.Errorf("title: got %q", pd.Title)
	}
}

func TestRegisterRoutes_PublicKey_CacheHitSkipsKMS(t *testing.T) {
	cfg := LoadConfig()
	cfg.CustodyKeyRingID = "projects/test/locations/loc/keyRings/ring"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	api.publicKeyCachePut("cachedshort", "-----BEGIN FAKE-----", "ES256")
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/keys/cachedshort/public", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from cache, got %d", rec.Code)
	}
	var resp PublicKeyResponse
	if err := custodianCBORdm.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	if resp.KeyID != "cachedshort" {
		t.Errorf("keyId: got %q", resp.KeyID)
	}
	if resp.PublicKey != "-----BEGIN FAKE-----" || resp.Alg != "ES256" {
		t.Errorf("unexpected body: %+v", resp)
	}
}

func TestRegisterRoutes_EnsureKey_Unauthorized(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(EnsureKeyRequest{KeyOwnerID: "owner1"})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", cborContentType)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}
}

func TestRegisterRoutes_EnsureKey_UnsupportedMediaType(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(EnsureKeyRequest{KeyOwnerID: "owner1"})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", rec.Code)
	}
}

func TestRegisterRoutes_EnsureKey_BadRequestInvalidSelfLogId(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(EnsureKeyRequest{KeyOwnerID: "owner1", SelfLogID: "not-a-uuid"})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", cborContentType)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestRegisterRoutes_EnsureKey_BadRequestReservedUserLabelPrefix(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(EnsureKeyRequest{
		KeyOwnerID: "11111111111111111111111111111111",
		SelfLogID:  "22222222-2222-2222-2222-222222222222",
		Labels:     map[string]string{"FO-test": "1"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", cborContentType)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for reserved fo- label prefix, got %d", rec.Code)
	}
}

func TestRegisterRoutes_EnsureKey_BadRequestMissingSelfLogId(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(EnsureKeyRequest{KeyOwnerID: "owner1"})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", cborContentType)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestRegisterRoutes_DeleteKey_RequiresBootstrap(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "normal"
	cfg.BootstrapAppToken = "bootstrap"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/keys/log-owner-foo/delete", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/keys/log-owner-foo/delete", nil)
	req2.Header.Set("Authorization", "Bearer normal")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with normal token, got %d", rec2.Code)
	}
}

func TestRegisterRoutes_ListKeys_RequiresNormalApp(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(ListKeysRequest{Labels: map[string]string{"fo-owner_id": "foo"}, Predicate: "and"})
	req := httptest.NewRequest(http.MethodPost, "/api/keys/list", bytes.NewReader(body))
	req.Header.Set("Content-Type", cborContentType)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}
}

func TestRegisterRoutes_ListKeysGet_RequiresLabelAndAuth(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/keys/list?fo-log_id=a1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/keys/list", nil)
	req2.Header.Set("Authorization", "Bearer secret")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 without labels, got %d", rec2.Code)
	}
}

func TestRegisterRoutes_CuratorLogKey_RequiresAuthAndLogId(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/keys/curator/log-key?logId=abc", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/keys/curator/log-key", nil)
	req2.Header.Set("Authorization", "Bearer secret")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 without logId, got %d", rec2.Code)
	}
}

func TestRegisterRoutes_SignKey_RequiresNormalApp(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/keys/log-owner-x/sign", nil)
	req.Header.Set("Content-Type", cborContentType)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}
}

func TestRegisterRoutes_DeleteKeyVersionsFrom_RequiresBootstrap(t *testing.T) {
	cfg := LoadConfig()
	cfg.BootstrapAppToken = "bootstrap"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(DeleteKeyVersionsFromRequest{Version: 2})
	req := httptest.NewRequest(http.MethodPost, "/api/keys/log-owner-foo/versions/delete-from", bytes.NewReader(body))
	req.Header.Set("Content-Type", cborContentType)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	cfg := LoadConfig()
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/keys/any/public", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when CUSTODY_KEY_RING_ID unset, got %d", rec.Code)
	}
}

func TestSignRequest_RawSignatureOnly_CBORRoundTrip(t *testing.T) {
	d := make([]byte, 32)
	for i := range d {
		d[i] = byte(i)
	}
	in := SignRequest{PayloadHash: d, RawSignatureOnly: true}
	b, err := custodianCBORem.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out SignRequest
	if err := custodianCBORdm.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !out.RawSignatureOnly || len(out.PayloadHash) != 32 {
		t.Fatalf("round trip mismatch: raw=%v hashLen=%d", out.RawSignatureOnly, len(out.PayloadHash))
	}
}

func TestCBORCodec_RoundTripEnsureKeyRequest(t *testing.T) {
	in := EnsureKeyRequest{
		KeyOwnerID: "o1",
		SelfLogID:  "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		Alg:        "ES256",
		Labels:     map[string]string{"k": "v"},
	}
	b, err := custodianCBORem.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out EnsureKeyRequest
	if err := custodianCBORdm.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.KeyOwnerID != in.KeyOwnerID || out.SelfLogID != in.SelfLogID ||
		out.Alg != in.Alg || out.Labels["k"] != "v" {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

const testEnsureSelfLogID = "11111111111111111111111111111111"

func TestRegisterRoutes_EnsureKey_CacheHitReturns200(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	cfg.CustodyKeyRingID = "projects/test/locations/loc/keyRings/ring"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	keyName := cfg.CustodyKeyRingID + "/cryptoKeys/" + testEnsureSelfLogID
	api.store.Set(testEnsureSelfLogID, KeyInfo{
		KeyID:        keyName,
		PublicKeyPEM: "-----BEGIN FAKE-----",
		Alg:          "ES256",
	})
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(EnsureKeyRequest{
		KeyOwnerID: testEnsureSelfLogID,
		SelfLogID:  testEnsureSelfLogID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", cborContentType)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from cache, got %d", rec.Code)
	}
	var resp EnsureKeyResponse
	if err := custodianCBORdm.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	if resp.Created {
		t.Error("expected created=false from cache hit")
	}
	if resp.PublicKey != "-----BEGIN FAKE-----" {
		t.Errorf("publicKey: got %q", resp.PublicKey)
	}
}

func TestRegisterRoutes_EnsureKey_OverrideExistingReturns200(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	cfg.CustodyKeyRingID = "projects/test/locations/loc/keyRings/ring"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	keyName := cfg.CustodyKeyRingID + "/cryptoKeys/" + testEnsureSelfLogID
	api.ensureKeyOverride = func(ctx context.Context, keyOwnerID, selfLogID, alg, protectionLevel string, labels map[string]string) (string, string, bool, error) {
		return keyName, "-----BEGIN OVERRIDE-----", false, nil
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(EnsureKeyRequest{
		KeyOwnerID: testEnsureSelfLogID,
		SelfLogID:  testEnsureSelfLogID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", cborContentType)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for existing key, got %d", rec.Code)
	}
	var resp EnsureKeyResponse
	if err := custodianCBORdm.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	if resp.Created {
		t.Error("expected created=false")
	}
}

func TestRegisterRoutes_EnsureKey_OverrideNewReturns201(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	cfg.CustodyKeyRingID = "projects/test/locations/loc/keyRings/ring"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	keyName := cfg.CustodyKeyRingID + "/cryptoKeys/" + testEnsureSelfLogID
	api.ensureKeyOverride = func(ctx context.Context, keyOwnerID, selfLogID, alg, protectionLevel string, labels map[string]string) (string, string, bool, error) {
		return keyName, "-----BEGIN NEW-----", true, nil
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(EnsureKeyRequest{
		KeyOwnerID: testEnsureSelfLogID,
		SelfLogID:  testEnsureSelfLogID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", cborContentType)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for new key, got %d", rec.Code)
	}
	var resp EnsureKeyResponse
	if err := custodianCBORdm.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	if !resp.Created {
		t.Error("expected created=true")
	}
}

func TestCBORCanonical_MapKeyOrder(t *testing.T) {
	// Two maps with same keys different construction order should encode identically.
	m1 := map[string]int{"a": 1, "b": 2}
	m2 := map[string]int{"b": 2, "a": 1}
	b1, _ := custodianCBORem.Marshal(m1)
	b2, _ := custodianCBORem.Marshal(m2)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("canonical encoding differs:\n%x\n%x", b1, b2)
	}
}

func TestProblemDetail_CBOR(t *testing.T) {
	pd := ProblemDetail{Type: "about:blank", Title: "x", Status: 400, Detail: "d"}
	b, err := custodianCBORem.Marshal(pd)
	if err != nil {
		t.Fatal(err)
	}
	var got ProblemDetail
	if err := custodianCBORdm.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != 400 || got.Title != "x" {
		t.Fatalf("%+v", got)
	}
}
