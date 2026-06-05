package univocity

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fxamacker/cbor/v2"
)

func TestHandleScopedRoot_ChainNotConfigured(t *testing.T) {
	logger, _ := NewLogger(0)
	pool, _ := NewContractClients(map[uint64]string{84532: "http://127.0.0.1:9"})
	defer pool.Close()
	api := API{Logger: logger, Pool: pool}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/99999/0x0000000000000000000000000000000000000001/root", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleScopedRoot_InvalidContract(t *testing.T) {
	logger, _ := NewLogger(0)
	pool := &mockPool{chain: &mockChain{}}
	api := API{Logger: logger, Pool: pool}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/84532/not-an-address/root", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAPI_ScopedAndLogIdShapes(t *testing.T) {
	logger, _ := NewLogger(0)
	rootID := [32]byte{0: 1}
	logID := [32]byte{0: 0, 31: 1}
	rootHex := LogIDToHex(rootID)
	logHex := LogIDToHex(logID)

	chain := &mockChain{
		rootLogId:      rootID,
		logInitialized: true,
		logConfig: LogConfig{
			Kind:          LogKindAuthority,
			AuthLogId:     rootID,
			RootKey:       make([]byte, 64),
			InitializedAt: 99,
		},
		logRootKeyX: [32]byte{1},
		logRootKeyY: [32]byte{2},
	}
	pool := &mockPool{chain: chain}

	registry := NewForestRegistry(logger, nil, map[uint64]string{84532: "http://example"}, time.Minute)
	registry.mu.Lock()
	registry.forests = []ForestEntry{{
		R:        rootID,
		ChainID:  84532,
		Contract: common.HexToAddress("0x0000000000000000000000000000000000000001"),
	}}
	registry.lastScan = time.Now()
	registry.mu.Unlock()

	resolver := NewForestResolver(logger, registry, pool, 100, time.Minute)

	api := API{Logger: logger, Pool: pool, Resolver: resolver}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	contract := "0x0000000000000000000000000000000000000001"

	t.Run("scoped root", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/84532/"+contract+"/root", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		var out struct {
			Exists    bool   `json:"exists"`
			RootLogId string `json:"rootLogId"`
		}
		_ = json.NewDecoder(rec.Body).Decode(&out)
		if !out.Exists || out.RootLogId != rootHex {
			t.Fatalf("unexpected %+v", out)
		}
	})

	t.Run("logId root", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+rootHex+"/root", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
		}
		var out struct {
			Exists    bool   `json:"exists"`
			RootLogId string `json:"rootLogId"`
		}
		_ = json.NewDecoder(rec.Body).Decode(&out)
		if !out.Exists || out.RootLogId != rootHex {
			t.Fatalf("unexpected %+v", out)
		}
	})

	t.Run("logId public-root CBOR", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+logHex+"/public-root", nil)
		req.Header.Set("Accept", "application/cbor")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
		}
		var record TrustRootResponse
		if err := cbor.Unmarshal(rec.Body.Bytes(), &record); err != nil {
			t.Fatalf("cbor: %v", err)
		}
		if record.Alg != "ES256" || len(record.X) != 32 || len(record.Y) != 32 {
			t.Fatalf("unexpected record %+v", record)
		}
	})

	t.Run("logId root before on-chain init via genesis identity", func(t *testing.T) {
		freshRoot := [32]byte{0: 9}
		freshHex := LogIDToHex(freshRoot)
		registry.mu.Lock()
		registry.forests = append(registry.forests, ForestEntry{
			R:        freshRoot,
			ChainID:  84532,
			Contract: common.HexToAddress(contract),
		})
		registry.mu.Unlock()
		resolver.OnRegistryScan()

		chain.logInitialized = false
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+freshHex+"/root", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		var out struct {
			Exists    bool   `json:"exists"`
			RootLogId string `json:"rootLogId"`
		}
		_ = json.NewDecoder(rec.Body).Decode(&out)
		if !out.Exists || out.RootLogId != freshHex {
			t.Fatalf("expected genesis short-circuit %+v", out)
		}
	})

	t.Run("logId unresolved 503", func(t *testing.T) {
		unknown := "0x00000000000000000000000000000000000000000000000000000000000000ab"
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+unknown+"/root", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", rec.Code)
		}
	})
}

func TestResolver_AmbiguousForest(t *testing.T) {
	logger, _ := NewLogger(0)
	logID := [32]byte{31: 1}
	chain := &mockChain{logInitialized: true}
	pool := &mockPool{chain: chain}
	registry := NewForestRegistry(logger, nil, map[uint64]string{84532: "x"}, time.Minute)
	registry.mu.Lock()
	registry.forests = []ForestEntry{
		{R: [32]byte{1}, ChainID: 84532, Contract: common.HexToAddress("0x1")},
		{R: [32]byte{2}, ChainID: 84532, Contract: common.HexToAddress("0x2")},
	}
	registry.lastScan = time.Now()
	registry.mu.Unlock()

	resolver := NewForestResolver(logger, registry, pool, 10, time.Minute)
	_, err := resolver.Resolve(context.Background(), logID)
	if err == nil || err != ErrAmbiguousForest {
		t.Fatalf("expected ErrAmbiguousForest, got %v", err)
	}
}

func TestHandleLogIDPublicRoot_UnavailableWithoutResolver(t *testing.T) {
	logger, _ := NewLogger(0)
	api := API{Logger: logger, Pool: &mockPool{chain: &mockChain{logInitialized: true}}}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	logHex := "0x0000000000000000000000000000000000000000000000000000000000000001"
	req := httptest.NewRequest(http.MethodGet, "/api/logs/"+logHex+"/public-root", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("expected 503, got %d %s", rec.Code, body)
	}
}
