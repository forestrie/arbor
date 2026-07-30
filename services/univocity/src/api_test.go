package univocity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
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
	var rootID logid.UUID
	rootID[0] = 1
	logID := testLogID(1)
	rootUUID := rootID.String()
	logUUID := logID.String()

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

	contract := "0x0000000000000000000000000000000000000001"

	boot, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	store := newFakeStore()
	store.genesis[rootUUID] = buildGenesisDoc(t, rootID, boot, 84532, common.HexToAddress(contract))
	store.index[logUUID] = rootID

	api := API{
		Logger:  logger,
		Pool:    pool,
		Store:   store,
		Forests: NewForestCache(100, time.Minute),
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

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
		if !out.Exists || out.RootLogId != rootUUID {
			t.Fatalf("unexpected %+v", out)
		}
	})

	t.Run("logId root", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+rootUUID+"/root", nil)
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
		if !out.Exists || out.RootLogId != rootUUID {
			t.Fatalf("unexpected %+v", out)
		}
	})

	t.Run("logId public-root CBOR", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+logUUID+"/public-root", nil)
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
		if record.Alg != coseAlgES256 || len(record.Key) != 64 {
			t.Fatalf("unexpected record alg=%d keyLen=%d", record.Alg, len(record.Key))
		}
	})

	t.Run("logId root before on-chain init via genesis identity", func(t *testing.T) {
		var freshRoot logid.UUID
		freshRoot[0] = 9
		freshUUID := freshRoot.String()
		store.genesis[freshUUID] = buildGenesisDoc(
			t, freshRoot, boot, 84532, common.HexToAddress(contract))

		chain.logInitialized = false
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+freshUUID+"/root", nil)
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
		if !out.Exists || out.RootLogId != freshUUID {
			t.Fatalf("expected genesis short-circuit %+v", out)
		}
	})

	t.Run("logId unresolved 404 with remedies", func(t *testing.T) {
		unknown, _ := logid.ParseUUIDString("00000000-0000-0000-0000-0000000000ab")
		req := httptest.NewRequest(http.MethodGet, "/api/logs/"+unknown.String()+"/root", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
		}
		body, _ := io.ReadAll(rec.Body)
		if !strings.Contains(string(body), "rootLogId") {
			t.Fatalf("404 body must name the rootLogId remedy: %s", body)
		}
	})
}

func TestHandleLogIDPublicRoot_UnavailableWithoutStore(t *testing.T) {
	logger, _ := NewLogger(0)
	api := API{Logger: logger, Pool: &mockPool{chain: &mockChain{logInitialized: true}}}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	logUUID := testLogID(1).String()
	req := httptest.NewRequest(http.MethodGet, "/api/logs/"+logUUID+"/public-root", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("expected 503, got %d %s", rec.Code, body)
	}
}
