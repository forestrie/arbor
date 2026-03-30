package custodian

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterRoutes_PublicKeyNotFound(t *testing.T) {
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
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != problemCBORType {
		t.Errorf("expected problem+cbor, got %q", ct)
	}
}

func TestRegisterRoutes_BootstrapPublic_503WhenBootstrapKeyIDEmpty(t *testing.T) {
	cfg := LoadConfig()
	cfg.BootstrapKMSCryptoKeyID = ""
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/keys/"+BootstrapKeyAlias+"/public", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when BOOTSTRAP_KMS_CRYPTO_KEY_ID unset, got %d", rec.Code)
	}
	var pd ProblemDetail
	if err := custodianCBORdm.Unmarshal(rec.Body.Bytes(), &pd); err != nil {
		t.Fatalf("problem body: %v", err)
	}
	if pd.Detail != "BOOTSTRAP_KMS_CRYPTO_KEY_ID not set" {
		t.Errorf("detail: got %q", pd.Detail)
	}
}

func TestRegisterRoutes_CreateKey_Unauthorized(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(CreateKeyRequest{KeyOwnerID: "owner1"})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", cborContentType)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}
}

func TestRegisterRoutes_CreateKey_UnsupportedMediaType(t *testing.T) {
	cfg := LoadConfig()
	cfg.AppToken = "secret"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := custodianCBORem.Marshal(CreateKeyRequest{KeyOwnerID: "owner1"})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", rec.Code)
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

	body, _ := custodianCBORem.Marshal(ListKeysRequest{Labels: map[string]string{"owner_id": "foo"}, Predicate: "and"})
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

	req := httptest.NewRequest(http.MethodGet, "/api/keys/list?forestrie_log_id=a1", nil)
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

func TestRegisterRoutes_SignBootstrap_RequiresBootstrapApp(t *testing.T) {
	cfg := LoadConfig()
	cfg.BootstrapAppToken = "boot"
	cfg.AppToken = "normal"
	logger, _ := NewLogger(0)
	api := NewAPI(logger, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/keys/"+BootstrapKeyAlias+"/sign", nil)
	req.Header.Set("Content-Type", cborContentType)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/keys/"+BootstrapKeyAlias+"/sign", nil)
	req2.Header.Set("Authorization", "Bearer normal")
	req2.Header.Set("Content-Type", cborContentType)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with normal token for bootstrap sign, got %d", rec2.Code)
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
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown key, got %d", rec.Code)
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

func TestCBORCodec_RoundTripCreateKeyRequest(t *testing.T) {
	in := CreateKeyRequest{KeyOwnerID: "o1", Alg: "ES256", Labels: map[string]string{"k": "v"}}
	b, err := custodianCBORem.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out CreateKeyRequest
	if err := custodianCBORdm.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.KeyOwnerID != in.KeyOwnerID || out.Alg != in.Alg || out.Labels["k"] != "v" {
		t.Fatalf("round trip mismatch: %+v", out)
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
