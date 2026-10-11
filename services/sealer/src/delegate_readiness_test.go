package sealer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// fakeRegisteredGauge records sealer_delegate_key_registered per epoch.
type fakeRegisteredGauge struct {
	mu  sync.Mutex
	set map[uint32]bool
}

func (g *fakeRegisteredGauge) SetDelegateKeyRegistered(epoch uint32, registered bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.set == nil {
		g.set = map[uint32]bool{}
	}
	g.set[epoch] = registered
}

// get returns the gauge value and whether the series exists.
func (g *fakeRegisteredGauge) get(epoch uint32) (registered, exported bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	registered, exported = g.set[epoch]
	return
}

// lookupAnswer is one scripted coordinator lookup outcome.
type lookupAnswer struct {
	registered bool
	err        error
}

// runnerHarness drives a delegateKeyRunner with millisecond timings and a
// scripted coordinator lookup.
type runnerHarness struct {
	t     *testing.T
	r     *delegateKeyRunner
	gauge *fakeRegisteredGauge

	mu       sync.Mutex
	events   []string // "install" and "lookup", in order
	installs []*DelegateKeySet
	answer   lookupAnswer
	lookups  int
}

func newRunnerHarness(t *testing.T) *runnerHarness {
	t.Helper()
	logger, _ := NewLogger(0)
	h := &runnerHarness{t: t, gauge: &fakeRegisteredGauge{}}
	h.r = &delegateKeyRunner{
		logger:    logger,
		epoch:     2,
		readiness: &DelegateKeyReadiness{},
		gauge:     h.gauge,
		install: func(k *DelegateKeySet) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.events = append(h.events, "install")
			h.installs = append(h.installs, k)
		},
		lookup: func(context.Context, string) (bool, string, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.events = append(h.events, "lookup")
			h.lookups++
			return h.answer.registered, "not registered", h.answer.err
		},
		loadBackoffStart:   time.Millisecond,
		loadBackoffMax:     2 * time.Millisecond,
		lookupBackoffStart: time.Millisecond,
		lookupBackoffMax:   2 * time.Millisecond,
		warnAfter:          time.Hour,
		reloadInterval:     time.Hour,
		now:                time.Now,
	}
	return h
}

// start runs the runner in the background, as StartDelegateKeysWithRetry
// does after its inline first attempt (keys non-nil when that succeeded).
func (h *runnerHarness) start(keys *DelegateKeySet) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	h.t.Cleanup(func() { cancel(); <-done })
	if keys != nil {
		h.r.installKeys(keys)
	}
	go func() { defer close(done); h.r.run(ctx, keys) }()
}

func (h *runnerHarness) setAnswer(a lookupAnswer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.answer = a
}

func (h *runnerHarness) lookupCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lookups
}

func (h *runnerHarness) installedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.installs)
}

func (h *runnerHarness) installed() *DelegateKeySet {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.installs[len(h.installs)-1]
}

func (h *runnerHarness) ready() bool {
	ok, _ := h.r.readiness.Ready()
	return ok
}

// Keys are installed before the coordinator is ever asked, so certificates
// bound to either epoch seal at once (ruling 1: install first, signal second).
func TestDelegateKeyRunner_InstallsBeforeLookup(t *testing.T) {
	keys := localKeys(t, 2)
	h := newRunnerHarness(t)
	h.r.load = func(context.Context) (*DelegateKeySet, error) { return keys, nil }
	h.start(nil)
	waitFor(t, "first lookup", func() bool { return h.lookupCount() >= 1 })
	h.mu.Lock()
	first := h.events[0]
	h.mu.Unlock()
	if first != "install" {
		t.Fatalf("first event = %q, want install before any lookup", first)
	}
}

// A 404 from the lookup keeps readiness at 503 and the gauge at 0 with the
// keys installed; a 200 flips both.
func TestDelegateKeyRunner_LookupGatesReadinessAndGauge(t *testing.T) {
	keys := localKeys(t, 2)
	h := newRunnerHarness(t)
	h.start(keys)

	waitFor(t, "several 404 polls", func() bool { return h.lookupCount() >= 3 })
	if h.ready() {
		t.Fatal("ready while the current key is unregistered")
	}
	if _, reason := h.r.readiness.Ready(); !strings.Contains(reason, "not registered") {
		t.Fatalf("reason = %q", reason)
	}
	if reg, exported := h.gauge.get(2); !exported || reg {
		t.Fatalf("gauge = (%v, exported %v), want 0", reg, exported)
	}
	if h.installedCount() != 1 {
		t.Fatal("keys must be installed while registration is pending")
	}

	h.setAnswer(lookupAnswer{registered: true})
	waitFor(t, "ready", h.ready)
	if reg, _ := h.gauge.get(2); !reg {
		t.Fatal("gauge must be 1 once registered")
	}
	n := h.lookupCount()
	time.Sleep(20 * time.Millisecond)
	if h.lookupCount() != n {
		t.Fatal("polling must stop once registered (until the next reload)")
	}
}

// A lookup error is "unknown", not "absent": it holds readiness but leaves
// the gauge where it was.
func TestDelegateKeyRunner_LookupErrorLeavesGauge(t *testing.T) {
	h := newRunnerHarness(t)
	h.setAnswer(lookupAnswer{err: errors.New("coordinator unreachable")})
	h.start(localKeys(t, 2))
	waitFor(t, "polls", func() bool { return h.lookupCount() >= 3 })
	if h.ready() {
		t.Fatal("ready without a confirmed registration")
	}
	if _, exported := h.gauge.get(2); exported {
		t.Fatal("a lookup error must not set the gauge")
	}
}

// Any boot fault holds readiness and polls; a retired current epoch is one
// (the sealer was bumped to a version that does not exist), and the runner
// recovers when the fault clears.
func TestDelegateKeyRunner_RetiredCurrentHoldsReadiness(t *testing.T) {
	keys := localKeys(t, 2)
	var retired atomic.Bool
	retired.Store(true)
	h := newRunnerHarness(t)
	h.setAnswer(lookupAnswer{registered: true})
	h.r.load = func(context.Context) (*DelegateKeySet, error) {
		if retired.Load() {
			return nil, fmt.Errorf("seed for epoch 2: %w", errDelegateSeedEpochRetired)
		}
		return keys, nil
	}
	h.start(nil)
	time.Sleep(20 * time.Millisecond)
	if h.ready() || h.installedCount() != 0 {
		t.Fatal("a retired current epoch must hold readiness with nothing installed")
	}
	if _, reason := h.r.readiness.Ready(); !strings.Contains(reason, "not loaded") {
		t.Fatalf("reason = %q", reason)
	}
	retired.Store(false)
	waitFor(t, "ready", h.ready)
}

// A failed daily reload keeps the installed set, readiness, and (while the
// lookup still confirms) the gauge.
func TestDelegateKeyRunner_ReloadFailureKeepsInstalledSet(t *testing.T) {
	keys := localKeys(t, 2)
	var loads atomic.Int32
	h := newRunnerHarness(t)
	h.r.reloadInterval = 5 * time.Millisecond
	h.setAnswer(lookupAnswer{registered: true})
	h.r.load = func(context.Context) (*DelegateKeySet, error) {
		loads.Add(1)
		return nil, errors.New("custodian down")
	}
	h.start(keys)
	waitFor(t, "ready", h.ready)
	waitFor(t, "two failed reloads", func() bool { return loads.Load() >= 2 })

	if h.installedCount() != 1 || h.installed() != keys {
		t.Fatal("a failed reload must not touch the installed set")
	}
	if !h.ready() {
		t.Fatal("readiness latches after boot")
	}
	if reg, _ := h.gauge.get(2); !reg {
		t.Fatal("gauge must stay 1 while the lookup still confirms registration")
	}
}

// After a reload the lookup is re-run; a 404 then drops the gauge to 0 but
// readiness stays latched (a registration lost after boot is the alert's job,
// not a reason to pull a working sealer).
func TestDelegateKeyRunner_ReloadRecheckDropsGaugeNotReadiness(t *testing.T) {
	keys := localKeys(t, 2)
	h := newRunnerHarness(t)
	h.r.reloadInterval = 5 * time.Millisecond
	h.setAnswer(lookupAnswer{registered: true})
	h.r.load = func(context.Context) (*DelegateKeySet, error) { return nil, errors.New("custodian down") }
	h.start(keys)
	waitFor(t, "ready", h.ready)

	h.setAnswer(lookupAnswer{registered: false})
	waitFor(t, "gauge 0", func() bool { reg, _ := h.gauge.get(2); return !reg })
	if !h.ready() {
		t.Fatal("readiness must stay latched after boot")
	}
}

// A successful reload that derives the same keys is a no-op on the key set.
func TestDelegateKeyRunner_ReloadSuccessIsNoOp(t *testing.T) {
	seed := testSeed(t)
	load := func(context.Context) (*DelegateKeySet, error) {
		return LoadDelegateKeys(context.Background(), localSeedProvider{secret: seed}, 2)
	}
	keys, _ := load(context.Background())
	var loads atomic.Int32
	h := newRunnerHarness(t)
	h.r.reloadInterval = 5 * time.Millisecond
	h.setAnswer(lookupAnswer{registered: true})
	h.r.load = func(ctx context.Context) (*DelegateKeySet, error) { loads.Add(1); return load(ctx) }
	h.start(keys)
	waitFor(t, "two reloads", func() bool { return loads.Load() >= 2 })
	if h.installedCount() != 1 || h.installed() != keys {
		t.Fatal("a successful reload must not reinstall keys")
	}
}

// A reload never uninstalls or replaces keys: a reload deriving a different
// key (the MAC key changed under the epoch, or a custodian rolled back) is
// refused, and the working set stays.
func TestDelegateKeyRunner_ReloadNeverReplacesKeys(t *testing.T) {
	keys := localKeys(t, 2)
	var loads atomic.Int32
	h := newRunnerHarness(t)
	h.r.reloadInterval = 5 * time.Millisecond
	h.setAnswer(lookupAnswer{registered: true})
	h.r.load = func(context.Context) (*DelegateKeySet, error) {
		loads.Add(1)
		return localKeys(t, 2), nil // fresh random seed: different keys
	}
	h.start(keys)
	waitFor(t, "two reloads", func() bool { return loads.Load() >= 2 })
	if h.installedCount() != 1 || h.installed() != keys {
		t.Fatal("a reload must never replace the installed set")
	}
	if !h.ready() {
		t.Fatal("a refused reload must not affect readiness")
	}
}

// With the test-only local seed there is no custodian registration to
// observe; the runner is ready once keys are installed and never polls.
func TestDelegateKeyRunner_LocalSeedReadyOnInstall(t *testing.T) {
	h := newRunnerHarness(t)
	h.r.lookup = nil
	h.start(localKeys(t, 2))
	waitFor(t, "ready", h.ready)
}

func TestDelegateKeyReadiness_DisabledIsReady(t *testing.T) {
	if ok, _ := (&DelegateKeyReadiness{disabled: true}).Ready(); !ok {
		t.Fatal("DELEGATE_KEY_EPOCH=0 must not hold readiness")
	}
	if ok, reason := (&DelegateKeyReadiness{}).Ready(); ok || reason == "" {
		t.Fatal("an enabled sealer with no keys must not be ready")
	}
}

// TestStartDelegateKeysWithRetry_EndToEnd wires a fake custodian and a fake
// coordinator: keys install before registration, the gauge is exported at 0
// from boot, and readiness follows the coordinator's lookup of the current
// key, which the sealer asks for by its pubkey hash with the coordinator
// bearer.
func TestStartDelegateKeysWithRetry_EndToEnd(t *testing.T) {
	custodian := fakeCustodian(t, nil, nil)
	var status atomic.Int32
	status.Store(http.StatusNotFound)
	var gotPath, gotAuth atomic.Value
	coordinator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		gotAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(coordinator.Close)

	logger, _ := NewLogger(0)
	cfg := Config{
		SealerID:                   "sealer-a",
		DelegateKeyEpoch:           2,
		DelegateSeedCustodianURL:   custodian.baseURL,
		DelegateSeedCustodianToken: "t",
		CoordinatorRegisterURL:     coordinator.URL,
		CoordinatorRegisterToken:   "coord-token",
	}
	leaseMgr := NewDelegationLeaseManager(nil, nil, 0, 0)
	gauge := &fakeRegisteredGauge{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	readiness := StartDelegateKeysWithRetry(ctx, custodian.httpClient, logger, cfg, leaseMgr, gauge)
	if leaseMgr.currentDelegateKey() == nil {
		t.Fatal("keys must be installed by the inline first attempt")
	}
	if reg, exported := gauge.get(2); !exported || reg {
		t.Fatal("gauge must be exported at 0 from boot")
	}
	if ok, _ := readiness.Ready(); ok {
		t.Fatal("ready before the coordinator confirmed registration")
	}

	wantHash, _ := pubkeyHashHex(&leaseMgr.currentDelegateKey().PublicKey)
	waitFor(t, "a lookup", func() bool { return gotPath.Load() != nil })
	if p := gotPath.Load().(string); p != "/api/sealer/delegate-keys/"+wantHash {
		t.Fatalf("lookup path = %q", p)
	}
	if a := gotAuth.Load().(string); a != "Bearer coord-token" {
		t.Fatalf("lookup auth = %q", a)
	}

	status.Store(http.StatusOK)
	waitFor(t, "ready", func() bool { ok, _ := readiness.Ready(); return ok })
	if reg, _ := gauge.get(2); !reg {
		t.Fatal("gauge must be 1 once registered")
	}
}

func TestStartDelegateKeysWithRetry_Disabled(t *testing.T) {
	logger, _ := NewLogger(0)
	gauge := &fakeRegisteredGauge{}
	r := StartDelegateKeysWithRetry(context.Background(), NewHTTPClient(logger), logger, Config{}, NewDelegationLeaseManager(nil, nil, 0, 0), gauge)
	if ok, _ := r.Ready(); !ok {
		t.Fatal("epoch 0 must be ready")
	}
	if _, exported := gauge.get(0); exported {
		t.Fatal("epoch 0 must not export the gauge")
	}
}

func TestCoordinatorDelegateKeyLookup(t *testing.T) {
	var status atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, `{"detail":"delegate key abc is registered on 3 of 4 shards; registration is incomplete"}`)
	}))
	t.Cleanup(srv.Close)
	logger, _ := NewLogger(0)
	l := coordinatorDelegateKeyLookup{baseURL: srv.URL + "/", token: "x", httpClient: NewHTTPClient(logger)}

	status.Store(http.StatusOK)
	if ok, _, err := l.Registered(context.Background(), "abc"); !ok || err != nil {
		t.Fatalf("200: ok=%v err=%v", ok, err)
	}
	status.Store(http.StatusNotFound)
	ok, detail, err := l.Registered(context.Background(), "abc")
	if ok || err != nil || !strings.Contains(detail, "3 of 4 shards") {
		t.Fatalf("404: ok=%v detail=%q err=%v", ok, detail, err)
	}
	status.Store(http.StatusUnauthorized)
	if ok, _, err := l.Registered(context.Background(), "abc"); ok || err == nil {
		t.Fatalf("401 must be an error, not absent: ok=%v err=%v", ok, err)
	}
}

// A 501 from the custodian (MAC key not yet verified) is a boot hold whose
// reason reaches the log.
func TestCustodianSeedProvider_ProblemDetailInError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := cbor.Marshal(map[string]any{"title": "misconfigured", "status": 501, "detail": "delegate seed MAC key not verified"})
		w.Header().Set("Content-Type", "application/problem+cbor")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	logger, _ := NewLogger(0)
	p := custodianSeedProvider{baseURL: srv.URL, token: "t", sealerID: "sealer-a", httpClient: NewHTTPClient(logger)}
	_, err := p.Seed(context.Background(), 2)
	if err == nil || !strings.Contains(err.Error(), "status=501") || !strings.Contains(err.Error(), "not verified") {
		t.Fatalf("err = %v", err)
	}
}
