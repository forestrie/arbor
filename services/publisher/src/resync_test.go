package publisher

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// step scripts one Assemble outcome for a key: either ready (submit) with a
// scripted SubmitOutcome, or a not-ready status.
type step struct {
	ready  bool
	status PublishStatus // when !ready
	submit SubmitOutcome // when ready: outcome the fake batch acks with
}

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
		f.pending = append(f.pending, readyItem{key: key, st: st})
		return []byte{0x01}, res, true, nil
	}
	return nil, res, false, nil
}

// SubmitBatch acks each request in order; batch order matches the FIFO of
// ready assembles, which is how the sweep constructs its batches.
func (f *fakeCore) SubmitBatch(_ context.Context, reqs []AssembledPublish) {
	for _, r := range reqs {
		f.mu.Lock()
		item := f.pending[0]
		f.pending = f.pending[1:]
		f.submits = append(f.submits, item.key)
		f.mu.Unlock()
		r.Ack(SubmitResult{Outcome: item.st.submit})
	}
}

// recordingMetrics pins the R3 acceptance: gap/handoff/sweep counters.
type recordingMetrics struct {
	mu       sync.Mutex
	gaps     int
	handoffs int
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
		poison: make(map[string]string),
	}
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
