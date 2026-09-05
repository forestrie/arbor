package publisher

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// syncBuffer is a goroutine-safe sink for captureLogger (submit-phase acks
// log from the batch goroutine).
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLogger returns a logger whose text output can be searched, so a test
// can pin what an OPERATOR sees — the alert line — not only what stats say.
func captureLogger() (*slog.Logger, *syncBuffer) {
	b := &syncBuffer{}
	return slog.New(slog.NewTextHandler(b, nil)), b
}

// strandedMsg is the operator-actionable alert; its text is part of the
// operational contract (grep targets, log-based alert rules).
const strandedMsg = "checkpoint aged out of resync horizon, still unanchored"

// strandedAlerts counts strand ERROR lines in captured output.
func strandedAlerts(b *syncBuffer) int {
	return strings.Count(b.String(), `level=ERROR msg="`+strandedMsg+`"`)
}

// step scripts one Assemble outcome for a key: either ready (submit) with a
// scripted SubmitOutcome, or a not-ready status.
type step struct {
	ready  bool
	status PublishStatus // when !ready
	submit SubmitOutcome // when ready: outcome the fake batch acks with
	reason string        // when submit==OutcomeReverted: decoded revert name
}

// stepRevertInvalid reverts with a calldata-invalid reason: the same bytes can
// never succeed, so the sweep must settle it rather than age it.
var stepRevertInvalid = step{ready: true, submit: OutcomeReverted, reason: "InvalidCheckpointCose"}

var (
	stepOwnerGated = step{status: StatusOwnerNotAnchored}
	stepAnchored   = step{status: StatusAlreadyAnchored}
	stepPublish    = step{ready: true, submit: OutcomePublished}
	stepRevert     = step{ready: true, submit: OutcomeReverted}
)

// fakeCore scripts Assemble per key (popping steps; last repeats) and acks
// every SubmitBatch request with the step's scripted outcome. All submission
// flows through SubmitBatch — there is no Submit here, mirroring sweepCore.
type readyItem struct {
	key string
	st  step
}

type fakeCore struct {
	mu        sync.Mutex
	seq       map[string][]step
	pending   []readyItem // ready assembles awaiting SubmitBatch, FIFO
	assembles []string
	submits   []string
}

func newFakeCore(seq map[string][]step) *fakeCore {
	return &fakeCore{seq: seq}
}

func (f *fakeCore) Assemble(_ context.Context, key string) ([]byte, PublishResult, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assembles = append(f.assembles, key)
	steps := f.seq[key]
	if len(steps) == 0 {
		return nil, PublishResult{}, false, fmt.Errorf("unscripted key %s", key)
	}
	st := steps[0]
	if len(steps) > 1 {
		f.seq[key] = steps[1:]
	}
	res := PublishResult{Key: key, Status: st.status}
	if st.ready {
		// Calldata carries the key so SubmitBatch can match the request to
		// its scripted outcome; a read-only assemble past the horizon leaves
		// its item unconsumed rather than shifting later submissions.
		f.pending = append(f.pending, readyItem{key: key, st: st})
		return []byte(key), res, true, nil
	}
	return nil, res, false, nil
}

// SubmitBatch acks each request with the outcome scripted for the key its
// calldata names.
func (f *fakeCore) SubmitBatch(_ context.Context, reqs []AssembledPublish) {
	for _, r := range reqs {
		key := string(r.Calldata)
		f.mu.Lock()
		found := -1
		for i, it := range f.pending {
			if it.key == key {
				found = i
				break
			}
		}
		if found < 0 {
			f.mu.Unlock()
			panic(fmt.Sprintf("SubmitBatch for %s without a ready assemble", key))
		}
		item := f.pending[found]
		f.pending = append(f.pending[:found], f.pending[found+1:]...)
		f.submits = append(f.submits, item.key)
		f.mu.Unlock()
		r.Ack(SubmitResult{Outcome: item.st.submit, Reason: item.st.reason})
	}
}

// recordingMetrics pins the R3 acceptance: gap/handoff/sweep counters.
type recordingMetrics struct {
	mu       sync.Mutex
	gaps     int
	handoffs int
	stranded int
	sweeps   map[string]int
}

func newRecordingMetrics() *recordingMetrics {
	return &recordingMetrics{sweeps: make(map[string]int)}
}
func (m *recordingMetrics) RecordResyncGap() { m.mu.Lock(); m.gaps++; m.mu.Unlock() }
func (m *recordingMetrics) RecordResyncHandoff() {
	m.mu.Lock()
	m.handoffs++
	m.mu.Unlock()
}
func (m *recordingMetrics) RecordResyncSweep(result string) {
	m.mu.Lock()
	m.sweeps[result]++
	m.mu.Unlock()
}
func (m *recordingMetrics) RecordResyncStranded(n int) {
	m.mu.Lock()
	m.stranded = n
	m.mu.Unlock()
}

// fakeLister serves pages keyed by continuation token, so token threading is
// pinned: asking with an unknown token is an error.
type fakeLister struct {
	pages map[string]s3.ListResult
	calls []string
	err   error
}

func (f *fakeLister) ListObjects(_ context.Context, _, token string, _ int) (s3.ListResult, error) {
	f.calls = append(f.calls, token)
	if f.err != nil {
		return s3.ListResult{}, f.err
	}
	p, ok := f.pages[token]
	if !ok {
		return s3.ListResult{}, fmt.Errorf("unexpected continuation token %q", token)
	}
	return p, nil
}

func ckpt(uuid string, index uint32) string {
	return fmt.Sprintf("v2/merklelog/checkpoints/14/%s/%016d.sth", uuid, index)
}

const (
	genesisLog = "85281f1d-21ee-217f-6405-de896ebeee60"
	robertLog  = "9cb53d26-6e22-4300-8274-d3f40a75a9fb"
	childLog   = "553d21cb-7642-45da-9e89-925b8d8f013f"
)

func page(keys ...string) s3.ListResult {
	var objs []s3.ObjectSummary
	for _, k := range keys {
		objs = append(objs, s3.ObjectSummary{Key: k, ETag: k + "#v1"})
	}
	return s3.ListResult{Objects: objs}
}

// pageAged builds a listing whose objects were written `age` ago, so the sweep
// horizon can be exercised without waiting.
func pageAged(age time.Duration, keys ...string) s3.ListResult {
	var objs []s3.ObjectSummary
	for _, k := range keys {
		objs = append(objs, s3.ObjectSummary{
			Key:          k,
			ETag:         k + "#v1",
			LastModified: time.Now().Add(-age).UTC().Format(time.RFC3339Nano),
		})
	}
	return s3.ListResult{Objects: objs}
}

func onePageAged(age time.Duration, keys ...string) *fakeLister {
	return &fakeLister{pages: map[string]s3.ListResult{"": pageAged(age, keys...)}}
}

func onePage(keys ...string) *fakeLister {
	return &fakeLister{pages: map[string]s3.ListResult{"": page(keys...)}}
}

func newTestResync(pub sweepCore, lister objectLister, m ResyncMetrics, h *OwnerGateHandoffs) *Resync {
	if m == nil {
		m = noopResyncMetrics{}
	}
	if h == nil {
		h = NewOwnerGateHandoffs()
	}
	return &Resync{
		pub: pub, lister: lister, interval: time.Minute, pageSize: 500,
		logger: testLogger(), metrics: m, handoffs: h,
		poison:  make(map[string]*poisonEntry),
		settled: make(map[string]*settledEntry),
		strands: make(map[string]*strandEntry),
	}
}

// pageMixed builds a listing with a per-key age, for logs whose seals
// straddle the horizon.
func pageMixed(ages map[string]time.Duration) *fakeLister {
	var objs []s3.ObjectSummary
	for k, age := range ages {
		objs = append(objs, s3.ObjectSummary{
			Key: k, ETag: k + "#v1",
			LastModified: time.Now().Add(-age).UTC().Format(time.RFC3339Nano),
		})
	}
	return &fakeLister{pages: map[string]s3.ListResult{"": {Objects: objs}}}
}

// agedLogs scripts n distinct aged genesis logs with the same step, for
// budget tests.
func agedLogs(n int, st step) (*fakeCore, *fakeLister) {
	seq := make(map[string][]step, n)
	keys := make([]string, 0, n)
	for i := 0; i < n; i++ {
		k := ckpt(fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i), 0)
		seq[k] = []step{st}
		keys = append(keys, k)
	}
	return newFakeCore(seq), onePageAged(resyncHorizon+time.Hour, keys...)
}

// TestSweepReplaysThe20260719Incident: genesis notification lost, children
// dead-lettered — one sweep anchors the whole forest root-first: genesis in
// pass 1, robert in pass 2, the child in pass 3. All three count as gaps (no
// handoffs recorded) and the metrics counter agrees (plan-2607-07 R3 AC).
func TestSweepReplaysThe20260719Incident(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(genesisLog, 0): {stepPublish, stepAnchored},
		ckpt(robertLog, 0):  {stepOwnerGated, stepPublish, stepAnchored},
		ckpt(childLog, 0):   {stepOwnerGated, stepOwnerGated, stepPublish},
	})
	m := newRecordingMetrics()
	r := newTestResync(pub, onePage(ckpt(genesisLog, 0), ckpt(robertLog, 0), ckpt(childLog, 0)), m, nil)

	stats, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Gaps != 3 || stats.Handoffs != 0 || stats.Blocked != 0 || stats.Errors != 0 {
		t.Fatalf("stats = %+v, want gaps=3 only", stats)
	}
	if m.gaps != 3 || m.handoffs != 0 {
		t.Fatalf("metrics gaps/handoffs = %d/%d, want 3/0", m.gaps, m.handoffs)
	}
}

// TestSweepClassifiesOwnerGateHandoffs: a key the consumer acked as
// owner-gated is anchored as a handoff, not a notification loss (W2/F7).
func TestSweepClassifiesOwnerGateHandoffs(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(genesisLog, 0): {stepPublish},
		ckpt(childLog, 0):   {stepOwnerGated, stepPublish},
	})
	m := newRecordingMetrics()
	h := NewOwnerGateHandoffs()
	h.Record(ckpt(childLog, 0))
	r := newTestResync(pub, onePage(ckpt(genesisLog, 0), ckpt(childLog, 0)), m, h)

	stats, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Gaps != 1 || stats.Handoffs != 1 {
		t.Fatalf("stats = %+v, want gaps=1 handoffs=1", stats)
	}
	if m.gaps != 1 || m.handoffs != 1 {
		t.Fatalf("metrics gaps/handoffs = %d/%d, want 1/1", m.gaps, m.handoffs)
	}
}

// TestSweepPoisonTopSealFallsBackToLowerMassif (W3): a reverted highest seal
// alerts and the publishable lower massif anchors in the same pass.
func TestSweepPoisonTopSealFallsBackToLowerMassif(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(robertLog, 1): {stepRevert},
		ckpt(robertLog, 0): {stepPublish},
	})
	m := newRecordingMetrics()
	r := newTestResync(pub, onePage(ckpt(robertLog, 0), ckpt(robertLog, 1)), m, nil)

	stats, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Unpublishable != 1 || stats.Gaps != 1 {
		t.Fatalf("stats = %+v, want unpublishable=1 gaps=1", stats)
	}
	if len(pub.submits) != 2 || pub.submits[0] != ckpt(robertLog, 1) || pub.submits[1] != ckpt(robertLog, 0) {
		t.Fatalf("submits = %v, want poison massif-1 then massif-0", pub.submits)
	}
}

// TestSweepHealthySteadyStateIsQuiet: everything already anchored — no gaps,
// no submissions, one assemble per coalesced log.
func TestSweepHealthySteadyStateIsQuiet(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(genesisLog, 0): {stepAnchored},
		ckpt(robertLog, 0):  {stepAnchored},
	})
	r := newTestResync(pub, onePage(ckpt(genesisLog, 0), ckpt(robertLog, 0)), nil, nil)

	stats, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Gaps != 0 || stats.Covered != 2 || len(pub.submits) != 0 {
		t.Fatalf("stats = %+v submits=%v, want covered=2 no submits", stats, pub.submits)
	}
}

// TestSweepCoalescesToHighestMassif: only the highest massif index per
// (height, log) is driven in the happy path; non-.sth keys are skipped.
func TestSweepCoalescesToHighestMassif(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(robertLog, 2): {stepAnchored},
	})
	r := newTestResync(pub, onePage(
		ckpt(robertLog, 0), ckpt(robertLog, 2), ckpt(robertLog, 1),
		"v2/merklelog/checkpoints/14/"+robertLog+"/not-a-checkpoint.txt",
	), nil, nil)

	stats, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Listed != 1 {
		t.Fatalf("Listed = %d, want 1 (one log group)", stats.Listed)
	}
	if len(pub.assembles) != 1 || pub.assembles[0] != ckpt(robertLog, 2) {
		t.Fatalf("assembles = %v, want exactly the index-2 key", pub.assembles)
	}
}

// TestSweepPaginates: continuation tokens must be threaded — the fake errors
// on an unexpected token, so a broken implementation cannot pass.
func TestSweepPaginates(t *testing.T) {
	p1 := page(ckpt(genesisLog, 0))
	p1.IsTruncated = true
	p1.NextContinuationToken = "t1"
	pub := newFakeCore(map[string][]step{
		ckpt(genesisLog, 0): {stepAnchored},
		ckpt(robertLog, 0):  {stepAnchored},
	})
	lister := &fakeLister{pages: map[string]s3.ListResult{"": p1, "t1": page(ckpt(robertLog, 0))}}
	r := newTestResync(pub, lister, nil, nil)

	stats, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Listed != 2 {
		t.Fatalf("Listed = %d, want 2", stats.Listed)
	}
	if len(lister.calls) != 2 || lister.calls[1] != "t1" {
		t.Fatalf("lister calls = %v, want token t1 threaded on the second call", lister.calls)
	}
}

// TestSweepListErrorSurfaces: a list failure is a sweep error (W4).
func TestSweepListErrorSurfaces(t *testing.T) {
	r := newTestResync(newFakeCore(nil), &fakeLister{err: fmt.Errorf("boom")}, nil, nil)
	if _, err := r.SweepOnce(context.Background()); err == nil {
		t.Fatalf("SweepOnce should surface the list error")
	}
}

// TestSweepContextCancellation: a cancelled ctx aborts the sweep with the
// context error (W4).
func TestSweepContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := newTestResync(newFakeCore(map[string][]step{ckpt(genesisLog, 0): {stepPublish}}),
		onePage(ckpt(genesisLog, 0)), nil, nil)
	if _, err := r.SweepOnce(ctx); err == nil {
		t.Fatalf("cancelled sweep should return the ctx error")
	}
}

// TestSweepUnresolvableOwnerBoundsPasses: an owner that never anchors leaves
// its child Blocked without spinning extra passes once progress stops.
func TestSweepUnresolvableOwnerBoundsPasses(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(genesisLog, 0): {stepPublish, stepAnchored},
		ckpt(childLog, 0):   {stepOwnerGated},
	})
	r := newTestResync(pub, onePage(ckpt(genesisLog, 0), ckpt(childLog, 0)), nil, nil)

	stats, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Gaps != 1 || stats.Blocked != 1 {
		t.Fatalf("stats = %+v, want gaps=1 blocked=1", stats)
	}
	// pass 1: both logs assembled; pass 2: child only (genesis settled);
	// pass 3 never runs (no progress in pass 2).
	if len(pub.assembles) != 3 {
		t.Fatalf("assembled %d times (%v), want 3", len(pub.assembles), pub.assembles)
	}
}

// TestRunRecordsHealthAndSweepResults (W2/W4): a successful sweep marks the
// backstop healthy and records sweeps_total{ok}; before any sweep it is
// unhealthy.
func TestRunRecordsHealthAndSweepResults(t *testing.T) {
	pub := newFakeCore(map[string][]step{ckpt(genesisLog, 0): {stepAnchored}})
	m := newRecordingMetrics()
	r := newTestResync(pub, onePage(ckpt(genesisLog, 0)), m, nil)
	r.interval = 10 * time.Millisecond

	if r.Healthy() {
		t.Fatalf("must be unhealthy before the first successful sweep")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	deadline := time.After(2 * time.Second)
	for !r.Healthy() {
		select {
		case <-deadline:
			t.Fatalf("never became healthy")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	m.mu.Lock()
	ok := m.sweeps["ok"]
	m.mu.Unlock()
	if ok == 0 {
		t.Fatalf("sweeps_total{ok} not recorded")
	}
}

// TestSweepPoisonCacheStopsReMining (rollout finding): a seal that mined a
// revert is cached at its ETag and never resubmitted while unchanged — the
// second sweep spends no gas and raises no new unpublishable count. A
// changed ETag (re-seal) clears it for exactly one fresh adjudication.
func TestSweepPoisonCacheStopsReMining(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(robertLog, 0): {stepRevert, stepPublish},
	})
	lister := onePage(ckpt(robertLog, 0))
	r := newTestResync(pub, lister, nil, nil)

	s1, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if s1.Unpublishable != 1 || len(pub.submits) != 1 {
		t.Fatalf("sweep1 = %+v submits=%v, want one mined revert", s1, pub.submits)
	}

	s2, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if len(pub.submits) != 1 {
		t.Fatalf("sweep 2 resubmitted the poison seal: submits=%v", pub.submits)
	}
	if s2.PoisonSkipped != 1 || s2.Unpublishable != 0 {
		t.Fatalf("sweep2 = %+v, want poisonSkipped=1 and no new unpublishable", s2)
	}

	// Re-seal: same key, new ETag — one fresh adjudication (which anchors).
	lister.pages[""] = s3.ListResult{Objects: []s3.ObjectSummary{{Key: ckpt(robertLog, 0), ETag: "v2"}}}
	s3res, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 3: %v", err)
	}
	if len(pub.submits) != 2 || s3res.Gaps != 1 {
		t.Fatalf("re-sealed key not re-adjudicated: submits=%v stats=%+v", pub.submits, s3res)
	}
}

// TestSweepSubmissionBudgetBoundsBurst (rollout finding): submissions per
// sweep are capped; over-budget logs are deferred, not submitted, so a large
// backlog cannot cascade receipt timeouts on the shared EOA.
func TestSweepSubmissionBudgetBoundsBurst(t *testing.T) {
	seq := make(map[string][]step)
	var keys []string
	for i := 0; i < resyncMaxSubmitsPerSweep+5; i++ {
		u := fmt.Sprintf("%08d-0000-4000-8000-%012d", i, i)
		k := ckpt(u, 0)
		keys = append(keys, k)
		seq[k] = []step{stepPublish}
	}
	pub := newFakeCore(seq)
	r := newTestResync(pub, onePage(keys...), nil, nil)

	stats, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if len(pub.submits) != resyncMaxSubmitsPerSweep {
		t.Fatalf("submitted %d, want budget %d", len(pub.submits), resyncMaxSubmitsPerSweep)
	}
	if stats.CapDeferred == 0 {
		t.Fatalf("stats = %+v, want CapDeferred > 0", stats)
	}
	// Classification is free: every group is still assembled even once the
	// submission budget is spent (budget-order refinement — a random-subset
	// sweep starved gap pickup behind the poison backlog on lane-a).
	if len(pub.assembles) != resyncMaxSubmitsPerSweep+5 {
		t.Fatalf("assembled %d groups, want all %d", len(pub.assembles), resyncMaxSubmitsPerSweep+5)
	}
}

// TestPoisonCacheAgeing (FOR-411): a poison entry past its backoff is
// re-adjudicated (one fresh submission); a further revert re-arms it with an
// incremented try count; a fresh entry stays skipped.
func TestPoisonCacheAgeing(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(robertLog, 0): {stepRevert, stepRevert, stepPublish},
	})
	lister := onePage(ckpt(robertLog, 0))
	r := newTestResync(pub, lister, nil, nil)

	if _, err := r.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if len(pub.submits) != 1 {
		t.Fatalf("sweep 1 should mine the revert once; submits=%v", pub.submits)
	}

	// Fresh entry: skipped.
	if s2, _ := r.SweepOnce(context.Background()); s2.PoisonSkipped != 1 || len(pub.submits) != 1 {
		t.Fatalf("fresh poison must be skipped; stats=%+v submits=%v", s2, pub.submits)
	}

	// Age the entry past its backoff: re-adjudicated (reverts again, tries++).
	r.poison[ckpt(robertLog, 0)].at = time.Now().Add(-2 * poisonRetryBase)
	if _, err := r.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep 3: %v", err)
	}
	if len(pub.submits) != 2 {
		t.Fatalf("aged poison must be re-adjudicated; submits=%v", pub.submits)
	}
	if e := r.poison[ckpt(robertLog, 0)]; e.tries != 1 {
		t.Fatalf("re-revert must increment tries; entry=%+v", e)
	}

	// Backoff doubles: not yet due at 1.5x base, due after 2x base elapses.
	r.poison[ckpt(robertLog, 0)].at = time.Now().Add(-poisonRetryBase - poisonRetryBase/2)
	if s5, _ := r.SweepOnce(context.Background()); s5.PoisonSkipped != 1 {
		t.Fatalf("tries=1 entry within doubled backoff must skip; stats=%+v", s5)
	}
	r.poison[ckpt(robertLog, 0)].at = time.Now().Add(-3 * poisonRetryBase)
	if _, err := r.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep 6: %v", err)
	}
	// Third adjudication publishes (transient revert resolved).
	if len(pub.submits) != 3 {
		t.Fatalf("expired doubled backoff must re-adjudicate; submits=%v", pub.submits)
	}
}

// TestResyncHorizonNeverDrivesAgedCandidates pins the bound that makes this
// backstop cheap: per-sweep work must track OUTSTANDING work, not total
// history. Before the horizon, a seal that could never publish stayed a
// candidate forever, so sweep cost grew with every checkpoint the platform had
// ever written. An aged candidate is classified (one read-only assemble) but
// never submitted: no gas, no nonce, no tx.
func TestResyncHorizonNeverDrivesAgedCandidates(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(robertLog, 0): {stepPublish},
	})
	lister := onePageAged(resyncHorizon+time.Hour, ckpt(robertLog, 0))
	r := newTestResync(pub, lister, nil, nil)

	stats, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.AgedOut != 1 || stats.Stranded != 1 || stats.AgedChecked != 1 {
		t.Fatalf("aged candidate must be counted and classified, not silently dropped; stats=%+v", stats)
	}
	if len(pub.submits) != 0 || len(pub.assembles) != 1 {
		t.Fatalf("aged candidate must be classified once and never driven; assembles=%v submits=%v",
			pub.assembles, pub.submits)
	}
}

// TestResyncHorizonAnchoredIsQuiet is the false alarm this horizon shipped
// with: "still unanchored" was asserted from AGE alone, so every checkpoint
// older than 12h — on lane A ~1,750 of them, all anchored — logged at ERROR
// every sweep and buried the real incidents the line exists to surface. An
// aged, anchored seal is the healthy shape of an old checkpoint: covered,
// quiet, and (via the settled cache) never re-assembled for the same bytes.
func TestResyncHorizonAnchoredIsQuiet(t *testing.T) {
	pub := newFakeCore(map[string][]step{ckpt(robertLog, 0): {stepAnchored}})
	lister := onePageAged(resyncHorizon+time.Hour, ckpt(robertLog, 0))
	r := newTestResync(pub, lister, nil, nil)
	logs := &syncBuffer{}
	r.logger, logs = captureLogger()

	s1, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if s1.AgedOut != 1 || s1.Covered != 1 || s1.Stranded != 0 || s1.AgedChecked != 1 {
		t.Fatalf("aged+anchored must be covered, not stranded; stats=%+v", s1)
	}
	if n := strandedAlerts(logs); n != 0 {
		t.Fatalf("anchored checkpoint must not alert; got %d strand ERRORs:\n%s", n, logs)
	}

	s2, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if s2.Covered != 1 || s2.AgedChecked != 0 || len(pub.assembles) != 1 {
		t.Fatalf("settled cache must make classification a once-per-content cost; stats=%+v assembles=%v",
			s2, pub.assembles)
	}
	if len(pub.submits) != 0 {
		t.Fatalf("no gas for an aged candidate; submits=%v", pub.submits)
	}
}

// TestResyncHorizonStrandedStillAlerts guards the other side of the fix: a
// genuine strand — publishable calldata the chain is still behind, past the
// horizon where nothing will submit it — MUST alert, and MUST be counted in
// every sweep's stranded total (the gauge), until an operator re-drive
// anchors it; then the recovery is logged and the seal stays cached. This is
// the FOR-408 strand shape (and today's InvalidPaymentReceipt logs, which
// assemble fine and revert on-chain). The ERROR fires on transition, not
// every sweep: the standing state is the count, not a repeated line.
func TestResyncHorizonStrandedStillAlerts(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(robertLog, 0): {stepPublish, stepPublish, stepAnchored},
	})
	lister := onePageAged(resyncHorizon+time.Hour, ckpt(robertLog, 0))
	r := newTestResync(pub, lister, nil, nil)
	logs := &syncBuffer{}
	r.logger, logs = captureLogger()

	for i := 1; i <= 2; i++ {
		st, err := r.SweepOnce(context.Background())
		if err != nil {
			t.Fatalf("sweep %d: %v", i, err)
		}
		if st.Stranded != 1 || st.Covered != 0 || st.AgedOut != 1 {
			t.Fatalf("sweep %d: unanchored aged seal must be counted stranded; stats=%+v", i, st)
		}
		if n := strandedAlerts(logs); n != 1 {
			t.Fatalf("sweep %d: strand alerts once on first verification; got %d ERRORs:\n%s", i, n, logs)
		}
	}
	if len(pub.assembles) != 1 {
		t.Fatalf("sweep 2 must count from the strand cache, not re-assemble; assembles=%v", pub.assembles)
	}
	if !strings.Contains(logs.String(), "status=publishable") {
		t.Fatalf("alert must say WHY it is stranded:\n%s", logs)
	}
	if len(pub.submits) != 0 {
		t.Fatalf("a strand is alerted, never driven past the horizon; submits=%v", pub.submits)
	}

	// Re-check due, same verdict: re-verified read-only, not re-logged.
	r.strands[ckpt(robertLog, 0)].at = time.Now().Add(-2 * strandRecheck)
	s3, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 3: %v", err)
	}
	if s3.Stranded != 1 || s3.StrandRechecks != 1 || s3.AgedChecked != 0 || strandedAlerts(logs) != 1 {
		t.Fatalf("unchanged verdict on re-check must not re-log; stats=%+v ERRORs=%d", s3, strandedAlerts(logs))
	}

	// Re-check due: the operator poke has landed.
	r.strands[ckpt(robertLog, 0)].at = time.Now().Add(-2 * strandRecheck)
	s3, err = r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 4: %v", err)
	}
	if s3.Stranded != 0 || s3.Covered != 1 || s3.StrandRechecks != 1 {
		t.Fatalf("anchored by re-drive must clear the strand; stats=%+v", s3)
	}
	if n := strandedAlerts(logs); n != 1 {
		t.Fatalf("no alert once anchored; got %d ERRORs", n)
	}
	if !strings.Contains(logs.String(), `level=INFO msg="stranded checkpoint now anchored"`) {
		t.Fatalf("recovery is the transition an operator waits for; must be logged:\n%s", logs)
	}
	if _, still := r.strands[ckpt(robertLog, 0)]; still {
		t.Fatalf("recovered strand must leave the strand cache")
	}
	s5, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 5: %v", err)
	}
	if s5.AgedChecked != 0 || len(pub.assembles) != 3 {
		t.Fatalf("recovered strand must be cached like any settled seal; stats=%+v assembles=%v",
			s5, pub.assembles)
	}
}

// TestResyncHorizonStrandsCannotStarveBudget: strands are re-verified on
// strandRecheck, not every sweep, so a lane with more persistent strands than
// the per-sweep check budget still classifies everything: the cached ones
// cost no checks, and the deferred remainder is reached next sweep.
func TestResyncHorizonStrandsCannotStarveBudget(t *testing.T) {
	const n = resyncMaxAgedChecksPerSweep + 6
	pub, lister := agedLogs(n, stepPublish)
	r := newTestResync(pub, lister, nil, nil)

	s1, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if s1.Stranded != resyncMaxAgedChecksPerSweep || s1.AgedDeferred != 6 {
		t.Fatalf("sweep 1 must strand the budget's worth and defer the rest; stats=%+v", s1)
	}
	s2, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if s2.Stranded != n || s2.AgedDeferred != 0 || s2.AgedChecked != 6 || len(pub.assembles) != n {
		t.Fatalf("sweep 2 must alert all from cache + verify the remainder; stats=%+v assembles=%d",
			s2, len(pub.assembles))
	}
}

// TestResyncHorizonRechecksDoNotStarveClassification: due re-checks spend
// their own (smaller) budget, so a large strand population cannot stall the
// warm-up of unclassified candidates, and a strand whose re-check is
// deferred still counts as stranded — its verdict stands until re-verified.
func TestResyncHorizonRechecksDoNotStarveClassification(t *testing.T) {
	const strands = resyncMaxStrandRechecksPerSweep + 4
	const fresh = 8
	seq := make(map[string][]step)
	keys := make([]string, 0, strands+fresh)
	for i := 0; i < strands+fresh; i++ {
		k := ckpt(fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i), 0)
		seq[k] = []step{stepPublish}
		keys = append(keys, k)
	}
	pub := newFakeCore(seq)
	r := newTestResync(pub, onePageAged(resyncHorizon+time.Hour, keys[:strands]...), nil, nil)
	if _, err := r.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	for _, e := range r.strands {
		e.at = time.Now().Add(-2 * strandRecheck) // every strand due
	}
	r.lister = onePageAged(resyncHorizon+time.Hour, keys...) // 8 new aged logs appear
	st, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if st.StrandRechecks != resyncMaxStrandRechecksPerSweep || st.AgedChecked != fresh || st.AgedDeferred != 0 {
		t.Fatalf("re-checks capped on their own budget, new logs all classified; stats=%+v", st)
	}
	if st.Stranded != strands+fresh {
		t.Fatalf("deferred re-checks still count as stranded; stats=%+v", st)
	}
}

// TestResyncHorizonResumesPastUncacheablePrefix: Assemble errors cache
// nothing, so with deterministic group order a prefix of >= budget failing
// logs would classify the same prefix every sweep and never reach the rest.
// The walk resumes where the budget ran out instead.
func TestResyncHorizonResumesPastUncacheablePrefix(t *testing.T) {
	const n = resyncMaxAgedChecksPerSweep + 6
	_, lister := agedLogs(n, stepPublish)
	pub := newFakeCore(map[string][]step{}) // every key unscripted: Assemble errors
	r := newTestResync(pub, lister, nil, nil)

	s1, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if s1.Errors != resyncMaxAgedChecksPerSweep || s1.AgedDeferred != 6 {
		t.Fatalf("sweep 1: stats=%+v", s1)
	}
	if _, err := r.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	seen := map[string]bool{}
	for _, k := range pub.assembles {
		seen[k] = true
	}
	if len(seen) != n {
		t.Fatalf("two sweeps must have reached every log at least once; reached %d of %d", len(seen), n)
	}
}

// TestResyncHorizonDeferredTopIsNotSettledByLowerSeal: an unverified
// (deferred) top seal must not let a cached verdict on a lower massif settle
// the log — that would report a possible strand at the top as covered.
func TestResyncHorizonDeferredTopIsNotSettledByLowerSeal(t *testing.T) {
	const n = resyncMaxAgedChecksPerSweep
	filler, _ := agedLogs(n, stepAnchored)
	filler.seq[ckpt(robertLog, 1)] = []step{stepPublish} // would be a strand
	filler.seq[ckpt(robertLog, 0)] = []step{stepAnchored}
	keys := make([]string, 0, n+2)
	for k := range filler.seq {
		keys = append(keys, k)
	}
	// robertLog sorts after the zero-padded filler ids, so it is deferred.
	r := newTestResync(filler, onePageAged(resyncHorizon+time.Hour, keys...), nil, nil)
	r.cacheSettled(ckpt(robertLog, 0), ckpt(robertLog, 0)+"#v1") // lower seal verified earlier

	s1, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if s1.AgedDeferred != 1 || s1.Covered != n || s1.Stranded != 0 {
		t.Fatalf("deferred top must count as deferred, not covered; stats=%+v", s1)
	}
	s2, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if s2.Stranded != 1 || s2.AgedDeferred != 0 {
		t.Fatalf("sweep 2 must verify the deferred top and find the strand; stats=%+v", s2)
	}
}

// TestResyncHorizonInWindowLowerSealStillDriven: a strand at the top must not
// starve a publishable in-window seal below it (an out-of-band rewrite can
// put one there). Pre-horizon the aged branch continued; so does this.
func TestResyncHorizonInWindowLowerSealStillDriven(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(robertLog, 1): {stepPublish}, // aged: strand
		ckpt(robertLog, 0): {stepPublish}, // fresh: must submit
	})
	lister := pageMixed(map[string]time.Duration{
		ckpt(robertLog, 1): resyncHorizon + time.Hour,
		ckpt(robertLog, 0): time.Hour,
	})
	r := newTestResync(pub, lister, nil, nil)

	st, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if st.Stranded != 1 || st.Gaps != 1 {
		t.Fatalf("top strands, lower publishes; stats=%+v", st)
	}
	if len(pub.submits) != 1 || pub.submits[0] != ckpt(robertLog, 0) {
		t.Fatalf("only the in-window seal is submitted; submits=%v", pub.submits)
	}
}

// TestResyncHorizonPoisonBackoffHonouredWhenAged: a seal poisoned in-window
// (FOR-411 backoff) that then ages out is a strand the chain already
// explained: alert with the cached reason, no round trips, until the backoff
// elapses and one fresh adjudication is due.
func TestResyncHorizonPoisonBackoffHonouredWhenAged(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(robertLog, 0): {{ready: true, submit: OutcomeReverted, reason: "InvalidPaymentReceipt"}, stepPublish},
	})
	r := newTestResync(pub, onePageAged(time.Hour, ckpt(robertLog, 0)), nil, nil)
	logs := &syncBuffer{}
	r.logger, logs = captureLogger()

	if _, err := r.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if len(pub.submits) != 1 {
		t.Fatalf("sweep 1 mines the revert; submits=%v", pub.submits)
	}
	r.lister = onePageAged(resyncHorizon+time.Hour, ckpt(robertLog, 0))
	s2, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if s2.Stranded != 1 || s2.AgedChecked != 0 || len(pub.assembles) != 1 {
		t.Fatalf("poisoned aged seal strands for free within backoff; stats=%+v assembles=%v", s2, pub.assembles)
	}
	if !strings.Contains(logs.String(), "reason=InvalidPaymentReceipt") {
		t.Fatalf("alert must carry the revert reason the chain gave:\n%s", logs)
	}

	// Both the poison backoff and the strand re-check are due.
	r.poison[ckpt(robertLog, 0)].at = time.Now().Add(-100 * poisonRetryMax)
	r.strands[ckpt(robertLog, 0)].at = time.Now().Add(-2 * strandRecheck)
	s3, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 3: %v", err)
	}
	if s3.Stranded != 1 || s3.StrandRechecks != 1 || len(pub.assembles) != 2 || len(pub.submits) != 1 {
		t.Fatalf("elapsed backoff re-verifies read-only, never re-mines; stats=%+v assembles=%v submits=%v",
			s3, pub.assembles, pub.submits)
	}
	// The verdict changed (reverted -> publishable): that transition is logged.
	if strandedAlerts(logs) != 2 || !strings.Contains(logs.String(), "status=publishable") {
		t.Fatalf("changed verdict must be re-logged once:\n%s", logs)
	}
}

// TestSettledCacheSkipsInWindowReassembly: an in-window seal verified
// anchored is not re-assembled every sweep for the 12h until it ages out —
// anchoring is monotonic, so the cached verdict is final for those bytes.
func TestSettledCacheSkipsInWindowReassembly(t *testing.T) {
	pub := newFakeCore(map[string][]step{ckpt(robertLog, 0): {stepAnchored}})
	r := newTestResync(pub, onePageAged(time.Hour, ckpt(robertLog, 0)), nil, nil)
	for i := 1; i <= 3; i++ {
		st, err := r.SweepOnce(context.Background())
		if err != nil {
			t.Fatalf("sweep %d: %v", i, err)
		}
		if st.Covered != 1 {
			t.Fatalf("sweep %d: stats=%+v", i, st)
		}
	}
	if len(pub.assembles) != 1 {
		t.Fatalf("one assemble, then cache; assembles=%v", pub.assembles)
	}
}

// TestResyncHorizonOwnerGatedIsStranded: the original 2026-07-19 incident
// shape — a genesis whose owner never anchored — is unanchored past the
// horizon and must alert with the owner-gate status, not be mistaken for
// covered because the assemble was not "ready".
func TestResyncHorizonOwnerGatedIsStranded(t *testing.T) {
	pub := newFakeCore(map[string][]step{ckpt(childLog, 0): {stepOwnerGated}})
	lister := onePageAged(resyncHorizon+time.Hour, ckpt(childLog, 0))
	r := newTestResync(pub, lister, nil, nil)
	logs := &syncBuffer{}
	r.logger, logs = captureLogger()

	st, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if st.Stranded != 1 || st.Blocked != 0 {
		t.Fatalf("aged owner-gated seal is a strand, not a blocked candidate; stats=%+v", st)
	}
	if strandedAlerts(logs) != 1 || !strings.Contains(logs.String(), "status=owner_not_anchored") {
		t.Fatalf("alert must carry the owner-gate status:\n%s", logs)
	}
}

// TestResyncHorizonSettledCacheSurvivesAgeing: a seal the sweep saw anchored
// while in-window must not be re-assembled once it ages out — the normal
// life cycle of every healthy checkpoint. A re-seal (new ETag) misses the
// cache and is classified afresh.
func TestResyncHorizonSettledCacheSurvivesAgeing(t *testing.T) {
	pub := newFakeCore(map[string][]step{ckpt(robertLog, 0): {stepAnchored}})
	r := newTestResync(pub, onePageAged(time.Hour, ckpt(robertLog, 0)), nil, nil)

	s1, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if s1.Covered != 1 || s1.AgedOut != 0 || len(pub.assembles) != 1 {
		t.Fatalf("in-window anchored seal is covered; stats=%+v assembles=%v", s1, pub.assembles)
	}

	// Same object, now past the horizon (same ETag).
	r.lister = onePageAged(resyncHorizon+time.Hour, ckpt(robertLog, 0))
	s2, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if s2.AgedOut != 1 || s2.Covered != 1 || s2.AgedChecked != 0 || len(pub.assembles) != 1 {
		t.Fatalf("in-window verdict must carry across the horizon; stats=%+v assembles=%v",
			s2, pub.assembles)
	}

	// Re-sealed: new content at the same key must be classified afresh.
	resealed := onePageAged(resyncHorizon+time.Hour, ckpt(robertLog, 0))
	resealed.pages[""].Objects[0].ETag = "resealed#v2"
	r.lister = resealed
	s3, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 3: %v", err)
	}
	if s3.AgedChecked != 1 || len(pub.assembles) != 2 {
		t.Fatalf("new ETag must miss the settled cache; stats=%+v assembles=%v", s3, pub.assembles)
	}
}

// TestResyncHorizonCheckBudgetDefers bounds the post-restart warm-up: the
// settled cache is in-memory, so a fresh process meets every aged checkpoint
// at once (~1,750 on lane A). Classification is spread over sweeps rather
// than issued as one burst, and the deferred remainder is picked up next
// sweep — nothing is dropped, nothing is falsely alerted meanwhile.
func TestResyncHorizonCheckBudgetDefers(t *testing.T) {
	const logs = resyncMaxAgedChecksPerSweep + 6
	seq := make(map[string][]step, logs)
	keys := make([]string, 0, logs)
	for i := 0; i < logs; i++ {
		k := ckpt(fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i), 0)
		seq[k] = []step{stepAnchored}
		keys = append(keys, k)
	}
	pub := newFakeCore(seq)
	r := newTestResync(pub, onePageAged(resyncHorizon+time.Hour, keys...), nil, nil)
	logsOut := &syncBuffer{}
	r.logger, logsOut = captureLogger()

	s1, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if s1.AgedOut != logs || s1.AgedChecked != resyncMaxAgedChecksPerSweep ||
		s1.AgedDeferred != 6 || s1.Covered != resyncMaxAgedChecksPerSweep || s1.Stranded != 0 {
		t.Fatalf("sweep 1 must classify exactly the budget and defer the rest; stats=%+v", s1)
	}
	if strandedAlerts(logsOut) != 0 {
		t.Fatalf("deferred candidates must not be alerted as stranded:\n%s", logsOut)
	}

	s2, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if s2.AgedChecked != 6 || s2.AgedDeferred != 0 || s2.Covered != logs || len(pub.assembles) != logs {
		t.Fatalf("sweep 2 must finish the backlog from cache + remainder; stats=%+v assembles=%d",
			s2, len(pub.assembles))
	}
}

// TestResyncHorizonCalldataInvalidPoisonStrandsForFree: a seal the contract
// rejected on its bytes can never anchor at this ETag, so once it ages out
// the strand verdict is already known — alert with the cached reason, spend
// no round trips and no check budget. Only a re-seal changes the answer.
func TestResyncHorizonCalldataInvalidPoisonStrandsForFree(t *testing.T) {
	pub := newFakeCore(map[string][]step{ckpt(robertLog, 0): {stepRevertInvalid}})
	r := newTestResync(pub, onePageAged(time.Hour, ckpt(robertLog, 0)), nil, nil)
	logs := &syncBuffer{}
	r.logger, logs = captureLogger()

	if _, err := r.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if len(pub.submits) != 1 || r.poison[ckpt(robertLog, 0)] == nil {
		t.Fatalf("sweep 1 mines the revert once and caches poison; submits=%v", pub.submits)
	}

	r.lister = onePageAged(resyncHorizon+time.Hour, ckpt(robertLog, 0))
	s2, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if s2.Stranded != 1 || s2.AgedChecked != 0 || len(pub.assembles) != 1 {
		t.Fatalf("known-invalid aged seal is stranded without a check; stats=%+v assembles=%v",
			s2, pub.assembles)
	}
	if strandedAlerts(logs) != 1 || !strings.Contains(logs.String(), "reason=InvalidCheckpointCose") {
		t.Fatalf("alert must carry the cached revert reason:\n%s", logs)
	}
}

// TestResyncHorizonUnconfiguredChainIsNotStranded: "stranded" is a verified
// verdict. A forest bound to a chain this publisher cannot read (D3) is
// unverifiable — an error and a WARN, as in-window — not a strand ERROR that
// would send an operator to re-drive something the chain may already hold.
func TestResyncHorizonUnconfiguredChainIsNotStranded(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(robertLog, 0): {{status: StatusChainNotConfigured}},
	})
	r := newTestResync(pub, onePageAged(resyncHorizon+time.Hour, ckpt(robertLog, 0)), nil, nil)
	logs := &syncBuffer{}
	r.logger, logs = captureLogger()

	st, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if st.Stranded != 0 || st.Errors != 1 || st.AgedChecked != 1 {
		t.Fatalf("unconfigured chain is an error, not a strand; stats=%+v", st)
	}
	if strandedAlerts(logs) != 0 || !strings.Contains(logs.String(), "status=chain_not_configured") {
		t.Fatalf("expected a WARN skip, no strand ERROR:\n%s", logs)
	}
}

// TestRunRecordsStrandedGauge: the strand count is exported per sweep so an
// alert rule can fire on it rather than on log volume.
func TestRunRecordsStrandedGauge(t *testing.T) {
	pub := newFakeCore(map[string][]step{ckpt(robertLog, 0): {stepPublish}})
	m := newRecordingMetrics()
	r := newTestResync(pub, onePageAged(resyncHorizon+time.Hour, ckpt(robertLog, 0)), m, nil)
	r.interval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	deadline := time.After(2 * time.Second)
	for !r.Healthy() {
		select {
		case <-deadline:
			t.Fatalf("never became healthy")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stranded != 1 {
		t.Fatalf("resync_stranded gauge must reflect the last sweep; got %d", m.stranded)
	}
}

// TestResyncHorizonKeepsFreshCandidates guards the other direction: the
// horizon must not weaken the notification-loss guarantee for anything still
// inside the window.
func TestResyncHorizonKeepsFreshCandidates(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(robertLog, 0): {stepPublish},
	})
	lister := onePageAged(resyncHorizon-time.Hour, ckpt(robertLog, 0))
	r := newTestResync(pub, lister, nil, nil)

	stats, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.AgedOut != 0 {
		t.Fatalf("in-window candidate must not age out; stats=%+v", stats)
	}
	if len(pub.submits) != 1 {
		t.Fatalf("in-window candidate must still be driven; submits=%v", pub.submits)
	}
}

// TestUnparseableTimestampIsNotAgedOut: a backend whose LastModified we cannot
// parse must not cause candidates to vanish. Failing open here costs a little
// wasted work; failing closed would silently strand logs, which is the exact
// FOR-408 harm the sweep exists to prevent.
func TestUnparseableTimestampIsNotAgedOut(t *testing.T) {
	pub := newFakeCore(map[string][]step{ckpt(robertLog, 0): {stepPublish}})
	lister := &fakeLister{pages: map[string]s3.ListResult{"": {
		Objects: []s3.ObjectSummary{{
			Key: ckpt(robertLog, 0), ETag: "e#v1", LastModified: "not-a-timestamp",
		}},
	}}}
	r := newTestResync(pub, lister, nil, nil)

	stats, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.AgedOut != 0 || len(pub.submits) != 1 {
		t.Fatalf("unparseable timestamp must fail OPEN; stats=%+v submits=%v", stats, pub.submits)
	}
}

// TestCalldataInvalidPoisonNeverAges: TestPoisonCacheAgeing proves a poison
// entry is re-adjudicated once its backoff elapses. That is right for a seal
// that might become publishable — and wrong for one the contract rejected on
// its bytes, where re-mining only burns gas to re-prove a settled fact.
func TestCalldataInvalidPoisonNeverAges(t *testing.T) {
	pub := newFakeCore(map[string][]step{
		ckpt(robertLog, 0): {stepRevertInvalid, stepPublish},
	})
	r := newTestResync(pub, onePage(ckpt(robertLog, 0)), nil, nil)

	if _, err := r.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if len(pub.submits) != 1 {
		t.Fatalf("sweep 1 mines the revert once; submits=%v", pub.submits)
	}
	if e := r.poison[ckpt(robertLog, 0)]; e == nil || !e.calldataInvalid {
		t.Fatalf("revert reason must latch calldataInvalid; entry=%+v", e)
	}

	// Age it far past any backoff. An ageing entry would re-adjudicate here.
	r.poison[ckpt(robertLog, 0)].at = time.Now().Add(-100 * poisonRetryMax)
	s2, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if s2.PoisonSkipped != 1 || len(pub.submits) != 1 {
		t.Fatalf("calldata-invalid poison must never re-adjudicate; stats=%+v submits=%v",
			s2, pub.submits)
	}
}

// TestRevertClassification pins the split. The membership that matters most is
// the NEGATIVE one: InvalidPaymentReceipt is retryable-in-principle, because
// funding or registering the instance makes the identical checkpoint valid.
// Classifying it as permanently invalid would settle accounts that are one
// operator action away from working.
func TestRevertClassification(t *testing.T) {
	for _, name := range []string{
		"InvalidCheckpointCose", "SignatureVerificationFailed",
		"DelegationSignatureInvalid", "ReceiptLogIdMismatch", "UnsupportedAlgorithm",
	} {
		if !RevertIsCalldataInvalid(name) {
			t.Errorf("%s is a property of the submitted bytes; must be calldata-invalid", name)
		}
	}
	for _, name := range []string{
		"InvalidPaymentReceipt",               // funding the instance fixes it
		"MissingDelegationCert",               // a later certificate fixes it
		"CheckpointIndexOutOfDelegationRange", // a wider certificate fixes it
		"LogNotFound", "NotInitialized",       // owner ordering fixes it
		"InvalidConsistencyProof",   // a re-seal on the moved base fixes it
		"",                          // unknown/empty: never settle on ignorance
		"SomeErrorAddedNextQuarter", // unrecognised: fall through to retry
	} {
		if RevertIsCalldataInvalid(name) {
			t.Errorf("%q can resolve without new calldata; must NOT be calldata-invalid", name)
		}
	}
}
