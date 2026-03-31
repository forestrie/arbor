package univocity

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockChain implements ChainReader for tests (plan §8.2, §8.7 verification).
type mockChain struct {
	rootLogId                [32]byte
	logInitialized           bool
	logConfig                LogConfig
	logRootKeyX, logRootKeyY [32]byte
}

func (m *mockChain) RootLogId(context.Context) ([32]byte, error) {
	return m.rootLogId, nil
}

func (m *mockChain) IsLogInitialized(_ context.Context, _ [32]byte) (bool, error) {
	return m.logInitialized, nil
}

func (m *mockChain) LogConfig(_ context.Context, _ [32]byte) (LogConfig, error) {
	return m.logConfig, nil
}

func (m *mockChain) LogRootKey(_ context.Context, _ [32]byte) ([32]byte, [32]byte, error) {
	return m.logRootKeyX, m.logRootKeyY, nil
}

func TestHandleRoot_UnavailableWhenChainNotConfigured(t *testing.T) {
	logger, _ := NewLogger(0)
	api := API{Logger: logger, Chain: nil}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/root", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 503 when chain not configured, got %d, body=%s", resp.StatusCode, string(body))
	}
}

// TestAPI_ResponseShapes verifies all endpoints return JSON shapes per plan §7.1 (step 8.7).
func TestAPI_ResponseShapes(t *testing.T) {
	logger, _ := NewLogger(0)
	rootZero := &mockChain{rootLogId: [32]byte{}}
	rootNonZero := &mockChain{
		rootLogId: [32]byte{0: 1},
	}
	rootNonZeroHex := LogIDToHex(rootNonZero.rootLogId)

	t.Run("GET /api/root not bootstrapped", func(t *testing.T) {
		api := API{Logger: logger, Chain: rootZero}
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		req := httptest.NewRequest(http.MethodGet, "/api/root", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d", rec.Code)
		}
		var out struct {
			Exists    bool   `json:"exists"`
			RootLogId string `json:"rootLogId"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Exists != false || out.RootLogId != "" {
			t.Errorf("expected exists=false, rootLogId=\"\"; got exists=%v rootLogId=%q", out.Exists, out.RootLogId)
		}
	})

	t.Run("GET /api/root bootstrapped", func(t *testing.T) {
		api := API{Logger: logger, Chain: rootNonZero}
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		req := httptest.NewRequest(http.MethodGet, "/api/root", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d", rec.Code)
		}
		var out struct {
			Exists    bool   `json:"exists"`
			RootLogId string `json:"rootLogId"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !out.Exists || out.RootLogId != rootNonZeroHex {
			t.Errorf("expected exists=true, rootLogId=%q; got exists=%v rootLogId=%q", rootNonZeroHex, out.Exists, out.RootLogId)
		}
	})

	t.Run("GET /api/logs not bootstrapped", func(t *testing.T) {
		api := API{Logger: logger, Chain: rootZero}
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		req := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d", rec.Code)
		}
		var out struct {
			RootLogId *string  `json:"rootLogId"`
			AuthLogs  []string `json:"authLogs"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.RootLogId != nil {
			t.Errorf("expected rootLogId null when not bootstrapped; got %v", *out.RootLogId)
		}
		if len(out.AuthLogs) != 0 {
			t.Errorf("expected authLogs []; got %v", out.AuthLogs)
		}
	})

	t.Run("GET /api/logs bootstrapped", func(t *testing.T) {
		api := API{Logger: logger, Chain: rootNonZero}
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		req := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d", rec.Code)
		}
		var out struct {
			RootLogId *string  `json:"rootLogId"`
			AuthLogs  []string `json:"authLogs"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.RootLogId == nil || *out.RootLogId != rootNonZeroHex {
			t.Errorf("expected rootLogId %q; got %v", rootNonZeroHex, out.RootLogId)
		}
		if len(out.AuthLogs) != 1 || out.AuthLogs[0] != rootNonZeroHex {
			t.Errorf("expected authLogs [%q]; got %v", rootNonZeroHex, out.AuthLogs)
		}
	})

	logIdHex := "0x0000000000000000000000000000000000000000000000000000000000000001"
	cfgInitialized := &mockChain{
		rootLogId:      [32]byte{},
		logInitialized: true,
		logConfig: LogConfig{
			Kind:          LogKindAuthority,
			AuthLogId:     [32]byte{},
			InitializedAt: 12345,
		},
		logRootKeyX: [32]byte{1},
		logRootKeyY: [32]byte{2},
	}
	cfgInitialized.logConfig.AuthLogId[31] = 2
	cfgNotInitialized := &mockChain{logInitialized: false}

	t.Run("GET /api/logs/{logId}/config 404 when not initialized", func(t *testing.T) {
		api := API{Logger: logger, Chain: cfgNotInitialized}
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+logIdHex+"/config", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("got status %d", rec.Code)
		}
	})

	t.Run("GET /api/logs/{logId}/config 200 and shape", func(t *testing.T) {
		api := API{Logger: logger, Chain: cfgInitialized}
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+logIdHex+"/config", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d", rec.Code)
		}
		var out struct {
			Kind          string `json:"kind"`
			AuthLogId     string `json:"authLogId"`
			InitializedAt uint64 `json:"initializedAt"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Kind != "authority" || out.InitializedAt != 12345 {
			t.Errorf("expected kind=authority, initializedAt=12345; got kind=%q initializedAt=%d", out.Kind, out.InitializedAt)
		}
		if out.AuthLogId != LogIDToHex(cfgInitialized.logConfig.AuthLogId) {
			t.Errorf("authLogId mismatch: got %q", out.AuthLogId)
		}
	})

	t.Run("GET /api/logs/{logId}/signing-key 404 when not initialized", func(t *testing.T) {
		api := API{Logger: logger, Chain: cfgNotInitialized}
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+logIdHex+"/signing-key", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("got status %d", rec.Code)
		}
	})

	t.Run("GET /api/logs/{logId}/signing-key 200 and shape", func(t *testing.T) {
		api := API{Logger: logger, Chain: cfgInitialized}
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+logIdHex+"/signing-key", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d", rec.Code)
		}
		var out struct {
			LogId      string `json:"logId"`
			Kind       string `json:"kind"`
			OwnerLogId string `json:"ownerLogId"`
			RootKeyX   string `json:"rootKeyX"`
			RootKeyY   string `json:"rootKeyY"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.LogId != logIdHex || out.Kind != "authority" {
			t.Errorf("logId or kind mismatch: logId=%q kind=%q", out.LogId, out.Kind)
		}
		if out.OwnerLogId != LogIDToHex(cfgInitialized.logConfig.AuthLogId) {
			t.Errorf("ownerLogId mismatch: got %q", out.OwnerLogId)
		}
		if out.RootKeyX != LogIDToHex(cfgInitialized.logRootKeyX) || out.RootKeyY != LogIDToHex(cfgInitialized.logRootKeyY) {
			t.Errorf("rootKeyX/Y mismatch")
		}
	})
}
