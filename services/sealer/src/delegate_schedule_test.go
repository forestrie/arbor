package sealer

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Runner tests for devdocs plan-2609-12 slice 05: a fake custodian (seed
// apiVersion 3 with vouchers) and a fake coordinator, millisecond timings.

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

// fakeCoordinator answers assertions per epoch (default 2xx) and keeps the
// rows a 2xx creates, so a test can delete them.
type fakeCoordinator struct {
	mu      sync.Mutex
	answers map[uint32]assertKind
	calls   map[uint32]int
	rows    map[uint32]registerDelegateKeyEntry
	events  *[]string
}

func newFakeCoordinator(events *[]string) *fakeCoordinator {
	return &fakeCoordinator{answers: map[uint32]assertKind{}, calls: map[uint32]int{}, rows: map[uint32]registerDelegateKeyEntry{}, events: events}
}

func (c *fakeCoordinator) assert(_ context.Context, sealerID string, key registerDelegateKeyEntry) assertResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.events = append(*c.events, "assert")
	c.calls[key.Epoch]++
	kind := c.answers[key.Epoch]
	if kind == assertOK {
		c.rows[key.Epoch] = key
	}
	return assertResult{kind: kind, status: 999, detail: "scripted"}
}

func (c *fakeCoordinator) answer(epoch uint32, k assertKind) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.answers[epoch] = k
}

func (c *fakeCoordinator) callCount(epoch uint32) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[epoch]
}

func (c *fakeCoordinator) row(epoch uint32) (registerDelegateKeyEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.rows[epoch]
	return r, ok
}

func (c *fakeCoordinator) deleteRows() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows = map[uint32]registerDelegateKeyEntry{}
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type runnerHarness struct {
	t     *testing.T
	r     *delegateKeyRunner
	cust  *fakeCustodianServer
	coord *fakeCoordinator
	gauge *fakeRegisteredGauge
	logs  *syncBuffer
	skew  atomic.Int64 // added to the runner's clock

	mu       sync.Mutex
	events   []string
	installs []*DelegateKeySet
}

func newRunnerHarness(t *testing.T, epoch uint32) *runnerHarness {
	t.Helper()
	h := &runnerHarness{t: t, cust: newFakeCustodian(t), gauge: &fakeRegisteredGauge{}, logs: &syncBuffer{}}
	h.coord = newFakeCoordinator(&h.events)
	logger := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	provider := h.cust.provider()
	h.r = &delegateKeyRunner{
		logger:    logger,
		sealerID:  "sealer-a",
		epoch:     epoch,
		readiness: NewDelegateKeyReadiness(),
		gauge:     h.gauge,
		load: func(ctx context.Context) (*DelegateKeySet, error) {
			return loadStandingKeys(ctx, logger, provider, epoch)
		},
		install: func(k *DelegateKeySet) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.events = append(h.events, "install")
			h.installs = append(h.installs, k)
		},
		loadBackoffStart:   time.Millisecond,
		loadBackoffMax:     2 * time.Millisecond,
		assertInterval:     5 * time.Millisecond,
		assertBackoffStart: time.Millisecond,
		assertBackoffMax:   5 * time.Millisecond,
		registeredFor:      50 * time.Millisecond,
		conflictLogEvery:   time.Hour,
		refreshAfter:       func(time.Duration) time.Duration { return time.Hour },
		refreshRetryAfter:  func(time.Duration) time.Duration { return 5 * time.Millisecond },
		now:                func() time.Time { return time.Now().Add(time.Duration(h.skew.Load())) },
	}
	h.r.assert = func(ctx context.Context, sealerID string, key registerDelegateKeyEntry) assertResult {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.coord.assert(ctx, sealerID, key)
	}
	return h
}

func (h *runnerHarness) start() {
	ctx, cancel := context.WithCancel(context.Background())
	h.r.start(ctx)
	h.t.Cleanup(func() { cancel(); h.r.wait() })
}

func (h *runnerHarness) installCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.installs)
}

func (h *runnerHarness) firstEvent() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.events[0]
}

func (h *runnerHarness) gaugeIs(epoch uint32, want bool) func() bool {
	return func() bool { v, ok := h.gauge.get(epoch); return ok && v == want }
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// Keys install before the coordinator is asked anything, so certificates
// bound to either epoch seal at once (change 1).
func TestDelegateKeyRunner_InstallsBeforeAnyAssertion(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.start()
	waitFor(t, "an assertion", func() bool { return h.coord.callCount(5) > 0 })
	if e := h.firstEvent(); e != "install" {
		t.Fatalf("first event = %q, want install", e)
	}
	if !h.r.readiness.Installed() {
		t.Fatal("keys must be marked installed")
	}
}

// Readiness is 503 until the current key's first 2xx, then latches.
func TestDelegateKeyRunner_ReadinessLatchesOnCurrentKey2xx(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.coord.answer(5, assertRetry)
	h.start()
	waitFor(t, "failed assertions", func() bool { return h.coord.callCount(5) >= 3 })
	if h.r.readiness.Ready() {
		t.Fatal("ready before the current key was asserted")
	}
	if code, _ := readyz(t, h.r.readiness); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503", code)
	}
	h.coord.answer(5, assertOK)
	waitFor(t, "ready", h.r.readiness.Ready)
	h.coord.answer(5, assertConflict)
	n := h.coord.callCount(5)
	waitFor(t, "post-latch assertions", func() bool { return h.coord.callCount(5) > n+2 })
	if !h.r.readiness.Ready() {
		t.Fatal("readiness must stay latched after boot")
	}
	waitFor(t, "gauge 0 after the post-latch 409", h.gaugeIs(5, false))
}

// An N-1 409 does not hold readiness; it sets only that epoch's gauge to 0.
func TestDelegateKeyRunner_PreviousConflictDoesNotHoldReadiness(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.coord.answer(4, assertConflict)
	h.start()
	waitFor(t, "ready", h.r.readiness.Ready)
	waitFor(t, "gauge 5 = 1", h.gaugeIs(5, true))
	waitFor(t, "N-1 asserted", func() bool { return h.coord.callCount(4) >= 2 })
	if v, ok := h.gauge.get(4); !ok || v {
		t.Fatalf("gauge 4 = (%v, %v), want 0", v, ok)
	}
}

// A current-key 409 holds readiness while the sealer keeps asserting, and it
// recovers without a restart once the conflict is cleared (operator delete).
func TestDelegateKeyRunner_CurrentConflictHoldsReadinessAndRecovers(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.coord.answer(5, assertConflict)
	h.start()
	waitFor(t, "repeated assertions under 409", func() bool { return h.coord.callCount(5) >= 4 })
	if h.r.readiness.Ready() {
		t.Fatal("a current-key 409 must hold readiness")
	}
	if v, ok := h.gauge.get(5); !ok || v {
		t.Fatal("a 409 sets the gauge to 0")
	}
	if n := strings.Count(h.logs.String(), "delegate key registration conflict"); n != 1 {
		t.Fatalf("conflict logged %d times within the 10 min window, want 1", n)
	}
	h.coord.answer(5, assertOK)
	waitFor(t, "ready", h.r.readiness.Ready)
	waitFor(t, "gauge 1", h.gaugeIs(5, true))
}

// A 410 stops assertions for that key only, for the life of the process.
func TestDelegateKeyRunner_TombstoneStopsThatKeyOnly(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.coord.answer(4, assertTombstoned)
	h.start()
	waitFor(t, "ready", h.r.readiness.Ready)
	n5 := h.coord.callCount(5)
	waitFor(t, "current key still asserted", func() bool { return h.coord.callCount(5) > n5+3 })
	if n := h.coord.callCount(4); n != 1 {
		t.Fatalf("tombstoned key asserted %d times, want 1", n)
	}
	if v, ok := h.gauge.get(4); !ok || v {
		t.Fatal("a 410 sets the gauge to 0")
	}
}

// A current-key 410 before the latch holds readiness.
func TestDelegateKeyRunner_CurrentTombstoneHoldsReadiness(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.coord.answer(5, assertTombstoned)
	h.start()
	waitFor(t, "the 410", func() bool { return h.coord.callCount(5) == 1 })
	time.Sleep(20 * time.Millisecond)
	if h.r.readiness.Ready() || h.coord.callCount(5) != 1 {
		t.Fatal("a current-key 410 holds readiness and stops asserting")
	}
}

// A row lost after boot (admin delete, coordinator reset) is re-created by
// the next assertion: the post-boot loss arbor#111 missed.
func TestDelegateKeyRunner_DeletedRowRecreated(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.start()
	waitFor(t, "ready", h.r.readiness.Ready)
	h.coord.deleteRows()
	waitFor(t, "rows re-created", func() bool {
		_, a := h.coord.row(5)
		_, b := h.coord.row(4)
		return a && b
	})
	row, _ := h.coord.row(5)
	if row.Alg != "ES256" || row.Voucher == "" || row.NotAfter <= time.Now().Unix() {
		t.Fatalf("row = %+v", row)
	}
}

// The assertion carries the installed key and the voucher's claim 4.
func TestDelegateKeyRunner_AssertionBody(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.start()
	waitFor(t, "row", func() bool { _, ok := h.coord.row(5); return ok })
	row, _ := h.coord.row(5)
	h.mu.Lock()
	keys := h.installs[0]
	h.mu.Unlock()
	coseKey, _ := delegateCoseKeyBytes(&keys.Current().PublicKey)
	if row.PublicKey != base64.StdEncoding.EncodeToString(coseKey) || row.Epoch != 5 {
		t.Fatalf("row = %+v", row)
	}
	v := keys.entries[0].voucher
	if row.NotAfter != v.NotAfter.Unix() || row.Voucher != base64.StdEncoding.EncodeToString(v.Raw) {
		t.Fatalf("row notAfter/voucher do not match the voucher: %+v", row)
	}
}

// The gauge falls to 0 once the last successful assertion is older than the
// registered window, when the coordinator becomes unreachable.
func TestDelegateKeyRunner_GaugeFallsWhenCoordinatorUnreachable(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.start()
	waitFor(t, "gauge 1", h.gaugeIs(5, true))
	h.coord.answer(5, assertRetry)
	h.coord.answer(4, assertRetry)
	waitFor(t, "gauge 0", h.gaugeIs(5, false))
	waitFor(t, "gauge 4 = 0", h.gaugeIs(4, false))
	if !h.r.readiness.Ready() {
		t.Fatal("readiness stays latched")
	}
}

// The gauge is exported at 0 from boot for the configured epoch, before any
// key loads (so the alert also catches a sealer that never installs).
func TestDelegateKeyRunner_GaugeExportedAtZeroFromBoot(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.cust.set(func(f *fakeCustodianServer) { f.down = true })
	h.start()
	if v, ok := h.gauge.get(5); !ok || v {
		t.Fatalf("gauge 5 = (%v, %v) at boot, want exported 0", v, ok)
	}
	if h.installCount() != 0 || h.r.readiness.Installed() {
		t.Fatal("nothing installs while the custodian is down")
	}
	h.cust.set(func(f *fakeCustodianServer) { f.down = false })
	waitFor(t, "ready", h.r.readiness.Ready)
}

// A voucher 400 refreshes vouchers at once, then retries at the backoff.
func TestDelegateKeyRunner_VoucherRefusedRefreshesNow(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.start()
	waitFor(t, "ready", h.r.readiness.Ready)
	before := h.cust.requestCount()
	h.coord.answer(5, assertVoucherRefused)
	waitFor(t, "gauge 0", h.gaugeIs(5, false))
	waitFor(t, "an immediate seed refresh", func() bool { return h.cust.requestCount() > before })
	h.coord.answer(5, assertOK)
	waitFor(t, "gauge 1", h.gaugeIs(5, true))
}

// A voucher that expires unrefreshed stops that key's assertions and drops
// its gauge to 0.
func TestDelegateKeyRunner_ExpiredVoucherStopsAssertions(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.start()
	waitFor(t, "ready", h.r.readiness.Ready)
	h.cust.set(func(f *fakeCustodianServer) { f.down = true })
	h.skew.Store(int64(48 * time.Hour))
	waitFor(t, "gauge 0", h.gaugeIs(5, false))
	n := h.coord.callCount(5)
	time.Sleep(30 * time.Millisecond)
	if h.coord.callCount(5) != n {
		t.Fatal("an expired voucher must stop assertions")
	}
	if h.installCount() != 1 {
		t.Fatal("keys stay installed")
	}
}

// A version-3 answer with no voucher installs the key, holds readiness, and
// re-requests the seed at the assertion backoff until a voucher arrives.
func TestDelegateKeyRunner_MissingVoucherInstallsAndRetries(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.cust.set(func(f *fakeCustodianServer) { f.noVoucher[5] = true })
	h.start()
	if h.installCount() != 1 {
		t.Fatal("the inline first attempt must install without a voucher")
	}
	before := h.cust.requestCount()
	waitFor(t, "seed retries", func() bool { return h.cust.requestCount() > before+4 })
	if h.r.readiness.Ready() || h.coord.callCount(5) != 0 {
		t.Fatal("no voucher: no assertion and no readiness")
	}
	h.cust.set(func(f *fakeCustodianServer) { f.noVoucher[5] = false })
	waitFor(t, "ready", h.r.readiness.Ready)
	if h.installCount() != 1 {
		t.Fatal("the voucher arriving must not reinstall keys")
	}
}

// A failed refresh keeps the installed keys and vouchers.
func TestDelegateKeyRunner_FailedRefreshKeepsKeysAndVouchers(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.r.refreshAfter = func(time.Duration) time.Duration { return 5 * time.Millisecond }
	h.start()
	waitFor(t, "ready", h.r.readiness.Ready)
	h.cust.set(func(f *fakeCustodianServer) { f.down = true })
	before := h.cust.requestCount()
	waitFor(t, "failed refreshes", func() bool { return h.cust.requestCount() > before+4 })
	n := h.coord.callCount(5)
	waitFor(t, "assertions continue", func() bool { return h.coord.callCount(5) > n+2 })
	waitFor(t, "gauge 1", h.gaugeIs(5, true))
	if h.installCount() != 1 {
		t.Fatal("a failed refresh must not touch the installed set")
	}
}

// A refresh adopts the new voucher when the reloaded key equals the
// installed key.
func TestDelegateKeyRunner_RefreshReplacesVoucher(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.r.refreshAfter = func(time.Duration) time.Duration { return 5 * time.Millisecond }
	h.start()
	waitFor(t, "row", func() bool { _, ok := h.coord.row(5); return ok })
	first, _ := h.coord.row(5)
	h.cust.set(func(f *fakeCustodianServer) { f.ttl = 48 * time.Hour })
	waitFor(t, "a refreshed voucher asserted", func() bool {
		r, _ := h.coord.row(5)
		return r.NotAfter > first.NotAfter+3600
	})
}

// A reload deriving a different key for an installed epoch is refused with
// an error log; the installed key and its voucher stay.
func TestDelegateKeyRunner_ReloadDifferentKeyRefused(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.r.refreshAfter = func(time.Duration) time.Duration { return 5 * time.Millisecond }
	h.start()
	waitFor(t, "row", func() bool { _, ok := h.coord.row(5); return ok })
	first, _ := h.coord.row(5)
	h.cust.set(func(f *fakeCustodianServer) { f.seedSalt = "other-mac-key" })
	waitFor(t, "refusal logged", func() bool {
		return strings.Contains(h.logs.String(), "reloaded delegate key differs from the installed key")
	})
	h.coord.deleteRows()
	waitFor(t, "row re-asserted", func() bool { _, ok := h.coord.row(5); return ok })
	if r, _ := h.coord.row(5); r.PublicKey != first.PublicKey {
		t.Fatal("assertions must keep the installed key")
	}
	if h.installCount() != 1 {
		t.Fatal("the installed set never changes after boot")
	}
}

// N-1 re-enabled after boot logs at info and installs nothing.
func TestDelegateKeyRunner_PreviousReenabledAfterBoot(t *testing.T) {
	h := newRunnerHarness(t, 5)
	h.r.refreshAfter = func(time.Duration) time.Duration { return 5 * time.Millisecond }
	h.cust.set(func(f *fakeCustodianServer) { f.retired[4] = true })
	h.start()
	waitFor(t, "ready", h.r.readiness.Ready)
	h.cust.set(func(f *fakeCustodianServer) { f.retired[4] = false })
	waitFor(t, "info log", func() bool {
		return strings.Contains(h.logs.String(), "level=INFO msg=\"delegate key epoch absent at boot is derivable again")
	})
	time.Sleep(20 * time.Millisecond)
	if h.installCount() != 1 || h.coord.callCount(4) != 0 {
		t.Fatal("an epoch absent at boot is never installed or asserted")
	}
	if _, ok := h.gauge.get(4); ok {
		t.Fatal("no gauge series for an epoch the sealer does not hold")
	}
}

// Boot faults hold readiness and retry: unreachable custodian, retired
// current epoch, a custodian below apiVersion 3.
func TestDelegateKeyRunner_BootFaultsHoldAndRetry(t *testing.T) {
	for name, fault := range map[string]func(f *fakeCustodianServer){
		"down":      func(f *fakeCustodianServer) { f.down = true },
		"retired N": func(f *fakeCustodianServer) { f.retired[5] = true },
		"v2":        func(f *fakeCustodianServer) { f.apiVersion = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			h := newRunnerHarness(t, 5)
			h.cust.set(fault)
			h.start()
			waitFor(t, "retries", func() bool { return h.cust.requestCount() > 4 })
			if h.installCount() != 0 || h.r.readiness.Installed() {
				t.Fatal("a boot fault installs nothing")
			}
			h.cust.set(func(f *fakeCustodianServer) {
				f.down, f.retired[5], f.apiVersion = false, false, delegateSeedAPIVersion
			})
			waitFor(t, "ready", h.r.readiness.Ready)
		})
	}
}

// With the test-only local seed there is no voucher and no registration:
// Ready once keys install, and no gauge.
func TestDelegateKeyRunner_LocalSeedReadyOnInstall(t *testing.T) {
	h := newRunnerHarness(t, 5)
	seed := testSeed(t)
	h.r.load = func(ctx context.Context) (*DelegateKeySet, error) {
		return LoadDelegateKeys(ctx, localSeedProvider{secret: seed}, 5)
	}
	h.r.assert = nil
	h.start()
	if !h.r.readiness.Ready() {
		t.Fatal("local seed: Ready on install")
	}
	if _, ok := h.gauge.get(5); ok {
		t.Fatal("local seed exports no gauge")
	}
}

// The refresh schedule is timed from the voucher: a quarter of its lifetime,
// and a twenty-fourth after a failure (6 h and 1 h at the 24 h default).
func TestVoucherRefreshDelays(t *testing.T) {
	if d := voucherRefreshAfter(24 * time.Hour); d != 6*time.Hour {
		t.Fatalf("refresh after %v", d)
	}
	if d := voucherRefreshRetryAfter(24 * time.Hour); d != time.Hour {
		t.Fatalf("retry after %v", d)
	}
}

// D1 (change 8), end to end through the production wiring: with the
// coordinator answering 409 the consumer-start hook never runs; once it
// answers 2xx, the hook runs exactly once.
func TestStartDelegateKeys_ConsumerStartsOnlyWhenReady(t *testing.T) {
	cust := newFakeCustodian(t)
	var status atomic.Int32
	status.Store(http.StatusConflict)
	var gotAuth atomic.Value
	coordinator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, `{"title":"Conflict","detail":"scripted"}`)
	}))
	t.Cleanup(coordinator.Close)

	logger, _ := NewLogger(0)
	cfg := Config{
		SealerID:                   "sealer-a",
		DelegateKeyEpoch:           5,
		DelegateSeedCustodianURL:   cust.srv.URL,
		DelegateSeedCustodianToken: "t",
		CoordinatorRegisterURL:     coordinator.URL,
		CoordinatorRegisterToken:   "coord-token",
	}
	leaseMgr := NewDelegationLeaseManager(&stubTrustRootClient{}, &pendingIssuerStub{}, time.Hour, time.Minute)
	readiness := NewDelegateKeyReadiness()
	gauge := &fakeRegisteredGauge{}
	r := newDelegateKeyRunner(cfg, NewHTTPClient(logger), logger, leaseMgr, readiness, gauge)
	r.assertInterval, r.assertJitter = 5*time.Millisecond, 0
	r.assertBackoffStart, r.assertBackoffMax = time.Millisecond, 5*time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); r.wait() })
	var starts atomic.Int32
	hookDone := readiness.RunWhenReady(ctx, func() { starts.Add(1) })
	r.start(ctx)

	if leaseMgr.delegateKeys == nil {
		t.Fatal("keys must be installed by the inline first attempt")
	}
	waitFor(t, "a 409", func() bool { a, _ := gotAuth.Load().(string); return a != "" })
	time.Sleep(30 * time.Millisecond)
	if n := starts.Load(); n != 0 {
		t.Fatalf("consumer started %d times under a current-key 409, want 0", n)
	}
	if a := gotAuth.Load().(string); a != "Bearer coord-token" {
		t.Fatalf("auth = %q", a)
	}

	status.Store(http.StatusOK)
	select {
	case <-hookDone:
	case <-time.After(3 * time.Second):
		t.Fatal("consumer never started after the coordinator answered 2xx")
	}
	time.Sleep(20 * time.Millisecond)
	if n := starts.Load(); n != 1 {
		t.Fatalf("consumer started %d times, want 1", n)
	}
	if v, ok := gauge.get(5); !ok || !v {
		t.Fatal("gauge must be 1 once asserted")
	}
}

// The local seed selects no assertion (change 9, decided from the provider).
func TestStartDelegateKeys_LocalSeedNoAssertion(t *testing.T) {
	logger, _ := NewLogger(0)
	cfg := Config{SealerID: "sealer-a", DelegateKeyEpoch: 3, DelegateSeedLocal: testSeed(t), CoordinatorRegisterURL: "https://unused.invalid"}
	readiness := NewDelegateKeyReadiness()
	gauge := &fakeRegisteredGauge{}
	leaseMgr := NewDelegationLeaseManager(&stubTrustRootClient{}, &pendingIssuerStub{}, time.Hour, time.Minute)
	r := newDelegateKeyRunner(cfg, NewHTTPClient(logger), logger, leaseMgr, readiness, gauge)
	if r.assert != nil {
		t.Fatal("local seed must not assert")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); r.wait() })
	r.start(ctx)
	if !readiness.Ready() {
		t.Fatal("local seed: Ready on install")
	}
	if _, err := leaseMgr.EnsureValidForLog(t.Context(), NewHTTPClient(nil), nil, "secp256r1",
		"0123456789abcdef0123456789abcdef", 0, 1); !errors.Is(err, ErrDelegationPending) {
		t.Fatalf("lease after keys: got %v want ErrDelegationPending", err)
	}
}
