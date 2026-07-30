package univocity

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
)

// resolveTestFixture wires an API whose resolution can only use point lookups
// against the fake store (plan-2607-10 slice 02/03 contract).
type resolveTestFixture struct {
	api   API
	store *fakeStore
	chain *mockChain
	mux   *http.ServeMux
}

func newResolveFixture(t *testing.T, negTTL time.Duration) *resolveTestFixture {
	t.Helper()
	logger, _ := NewLogger(0)
	chain := &mockChain{logInitialized: true}
	store := newFakeStore()
	api := API{
		Logger:  logger,
		Pool:    &mockPool{chain: chain},
		Store:   store,
		Forests: NewForestCache(100, negTTL),
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	return &resolveTestFixture{api: api, store: store, chain: chain, mux: mux}
}

func (f *resolveTestFixture) getRoot(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *resolveTestFixture) addForest(t *testing.T, r logid.UUID) {
	t.Helper()
	boot := mustKey(t)
	f.store.genesis[r.String()] = buildGenesisDoc(
		t, r, boot, 84532, common.HexToAddress("0x0000000000000000000000000000000000000001"))
}

func TestResolve_RCaseSelfHealsIndex(t *testing.T) {
	f := newResolveFixture(t, time.Minute)
	root := testLogID(1)
	f.addForest(t, root)

	rec := f.getRoot(t, "/api/logs/"+root.String()+"/root")
	if rec.Code != http.StatusOK {
		t.Fatalf("R case want 200 got %d body=%s", rec.Code, rec.Body.String())
	}
	if got, ok := f.store.index[root.String()]; !ok || got != root {
		t.Fatalf("R case must self-heal the R->R index entry, got %v ok=%v", got, ok)
	}
}

func TestResolve_DanglingLocatorIs404AndSelfHeals(t *testing.T) {
	f := newResolveFixture(t, time.Minute)
	subject := testLogID(2)
	ghost := testLogID(3)
	// Index names a forest whose genesis is gone (delete paths / pruning).
	f.store.index[subject.String()] = ghost

	rec := f.getRoot(t, "/api/logs/"+subject.String()+"/root")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("dangling locator want 404 got %d body=%s", rec.Code, rec.Body.String())
	}
	if _, still := f.store.index[subject.String()]; still {
		t.Fatal("dangling index entry must be self-heal deleted")
	}
}

func TestResolve_HintPaths(t *testing.T) {
	f := newResolveFixture(t, time.Minute)
	root := testLogID(4)
	subject := testLogID(5)
	f.addForest(t, root)
	f.store.grants[f.store.grantStoreKey(root, subject, GrantClassAuthLog)] = []byte{0x01}

	t.Run("valid subject hint resolves", func(t *testing.T) {
		rec := f.getRoot(t, "/api/logs/"+subject.String()+"/root?rootLogId="+root.String())
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200 got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("hint equal to logId is the R case", func(t *testing.T) {
		rec := f.getRoot(t, "/api/logs/"+root.String()+"/root?rootLogId="+root.String())
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200 got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("wrong hint names both ids", func(t *testing.T) {
		orphan := testLogID(6)
		rec := f.getRoot(t, "/api/logs/"+orphan.String()+"/root?rootLogId="+root.String())
		if rec.Code != http.StatusNotFound {
			t.Fatalf("want 404 got %d", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, orphan.String()) || !strings.Contains(body, root.String()) {
			t.Fatalf("404 for a wrong hint must name the log and the hinted forest: %s", body)
		}
	})

	t.Run("unknown hinted forest is 404", func(t *testing.T) {
		ghost := testLogID(7)
		rec := f.getRoot(t, "/api/logs/"+subject.String()+"/root?rootLogId="+ghost.String())
		if rec.Code != http.StatusNotFound {
			t.Fatalf("want 404 got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), ghost.String()) {
			t.Fatalf("404 must name the unknown hinted forest: %s", rec.Body.String())
		}
	})

	t.Run("malformed hint is 400", func(t *testing.T) {
		rec := f.getRoot(t, "/api/logs/"+subject.String()+"/root?rootLogId=not-a-uuid")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d", rec.Code)
		}
	})
}

func TestResolve_NegativeCacheBoundsVisibility(t *testing.T) {
	f := newResolveFixture(t, 50*time.Millisecond)
	root := testLogID(8)

	if rec := f.getRoot(t, "/api/logs/"+root.String()+"/root"); rec.Code != http.StatusNotFound {
		t.Fatalf("want initial 404 got %d", rec.Code)
	}
	f.addForest(t, root)
	// Still negatively cached: registration is not visible until the TTL.
	if rec := f.getRoot(t, "/api/logs/"+root.String()+"/root"); rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 within negative TTL got %d", rec.Code)
	}
	time.Sleep(60 * time.Millisecond)
	if rec := f.getRoot(t, "/api/logs/"+root.String()+"/root"); rec.Code != http.StatusOK {
		t.Fatalf("want 200 after negative TTL got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestResolve_NeverEnumerates pins the plan-2607-10 structural contract: no
// resolution outcome — hit, R case, dangling locator, hint, or miss — may
// list the store.
func TestResolve_NeverEnumerates(t *testing.T) {
	f := newResolveFixture(t, time.Minute)
	root := testLogID(9)
	f.addForest(t, root)
	f.store.index[testLogID(10).String()] = testLogID(11) // dangling

	paths := []string{
		"/api/logs/" + root.String() + "/root",
		"/api/logs/" + testLogID(10).String() + "/root",
		"/api/logs/" + testLogID(12).String() + "/root",
		"/api/logs/" + testLogID(13).String() + "/root?rootLogId=" + root.String(),
	}
	for _, p := range paths {
		f.getRoot(t, p)
	}
	if f.store.listCalls != 0 {
		t.Fatalf("resolution must never enumerate the store; saw %d list calls", f.store.listCalls)
	}
}

func TestPostGenesis_ClaimFirstRejectsBoundLogId(t *testing.T) {
	logger, _ := NewLogger(0)
	store := newFakeStore()
	api := API{
		Logger: logger,
		Store:  store,
		// Pool nil + AllowUnanchoredGenesis: anchor verification is skipped
		// so the test isolates the claim ordering.
		AllowUnanchoredGenesis: true,
		APIToken:               "token",
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	r := testLogID(20)
	other := testLogID(21)
	// The would-be forest root is already a subject in another forest.
	store.index[r.String()] = other

	boot := mustKS256Key(t)
	body := buildGenesisDocKS256(t, r, boot, 84532,
		common.HexToAddress("0x0000000000000000000000000000000000000002"))
	req := httptest.NewRequest(http.MethodPost, "/api/forest/"+r.String()+"/genesis",
		strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("claim-first want 409 got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.genesis) != 0 {
		t.Fatal("conflicting genesis must not be written (claim-first ordering)")
	}
}

func TestPostGenesis_ClaimFirstIdempotentRetry(t *testing.T) {
	logger, _ := NewLogger(0)
	store := newFakeStore()
	api := API{
		Logger:                 logger,
		Store:                  store,
		AllowUnanchoredGenesis: true,
		APIToken:               "token",
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	r := testLogID(22)
	boot := mustKS256Key(t)
	body := buildGenesisDocKS256(t, r, boot, 84532,
		common.HexToAddress("0x0000000000000000000000000000000000000003"))

	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/forest/"+r.String()+"/genesis",
			strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	if rec := post(); rec.Code != http.StatusCreated {
		t.Fatalf("first post want 201 got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := store.index[r.String()]; got != r {
		t.Fatalf("self-index must be claimed, got %v", got)
	}
	// Same-R retry: claim already held by R itself -> falls through to the
	// existing genesis-exists 409, index unchanged.
	if rec := post(); rec.Code != http.StatusConflict {
		t.Fatalf("retry want 409 genesis-exists got %d", rec.Code)
	}
}
