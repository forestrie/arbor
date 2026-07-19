package publisher

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeSweepPub scripts Publish outcomes per key: each call pops the next
// status in the key's sequence (the last repeats).
type fakeSweepPub struct {
	seq   map[string][]PublishStatus
	calls []string
}

func (f *fakeSweepPub) Publish(_ context.Context, key string) (PublishResult, error) {
	f.calls = append(f.calls, key)
	statuses := f.seq[key]
	if len(statuses) == 0 {
		return PublishResult{}, fmt.Errorf("unscripted key %s", key)
	}
	st := statuses[0]
	if len(statuses) > 1 {
		f.seq[key] = statuses[1:]
	}
	res := PublishResult{Key: key, Status: st}
	return res, nil
}

// fakeLister serves canned pages.
type fakeLister struct {
	pages []s3.ListResult
	calls int
}

func (f *fakeLister) ListObjects(_ context.Context, _, _ string, _ int) (s3.ListResult, error) {
	if f.calls >= len(f.pages) {
		return s3.ListResult{}, nil
	}
	p := f.pages[f.calls]
	f.calls++
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
		objs = append(objs, s3.ObjectSummary{Key: k})
	}
	return s3.ListResult{Objects: objs}
}

func newResync(pub oneShotPublisher, lister objectLister) *Resync {
	return &Resync{pub: pub, lister: lister, pageSize: 500, logger: testLogger(), metrics: noopResyncMetrics{}}
}

// TestSweepReplaysThe20260719Incident: genesis notification lost, children
// dead-lettered — the sweep must anchor the whole forest root-first in one
// SweepOnce: genesis in pass 1, robert in pass 2, the child in pass 3.
func TestSweepReplaysThe20260719Incident(t *testing.T) {
	pub := &fakeSweepPub{seq: map[string][]PublishStatus{
		ckpt(genesisLog, 0): {StatusPublished, StatusAlreadyAnchored},
		ckpt(robertLog, 0):  {StatusOwnerNotAnchored, StatusPublished, StatusAlreadyAnchored},
		ckpt(childLog, 0):   {StatusOwnerNotAnchored, StatusOwnerNotAnchored, StatusPublished},
	}}
	lister := &fakeLister{pages: []s3.ListResult{
		page(ckpt(genesisLog, 0), ckpt(robertLog, 0), ckpt(childLog, 0)),
	}}

	stats, err := newResync(pub, lister).SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Gaps != 3 {
		t.Fatalf("Gaps = %d, want 3 (genesis, robert, child all anchored by the sweep)", stats.Gaps)
	}
	if stats.Blocked != 0 || stats.Errors != 0 {
		t.Fatalf("Blocked/Errors = %d/%d, want 0/0", stats.Blocked, stats.Errors)
	}
}

// TestSweepHealthySteadyStateIsQuiet: everything already anchored — no gaps,
// no retries, one Publish per coalesced key.
func TestSweepHealthySteadyStateIsQuiet(t *testing.T) {
	pub := &fakeSweepPub{seq: map[string][]PublishStatus{
		ckpt(genesisLog, 0): {StatusAlreadyAnchored},
		ckpt(robertLog, 0):  {StatusAlreadyAnchored},
	}}
	lister := &fakeLister{pages: []s3.ListResult{page(ckpt(genesisLog, 0), ckpt(robertLog, 0))}}

	stats, err := newResync(pub, lister).SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Gaps != 0 || stats.Covered != 2 || stats.Blocked != 0 {
		t.Fatalf("stats = %+v, want covered=2 only", stats)
	}
	if len(pub.calls) != 2 {
		t.Fatalf("Publish called %d times, want 2", len(pub.calls))
	}
}

// TestSweepCoalescesToHighestMassif: only the highest massif index per
// (height, log) is driven — the anchored highest seal subsumes lower massifs.
func TestSweepCoalescesToHighestMassif(t *testing.T) {
	pub := &fakeSweepPub{seq: map[string][]PublishStatus{
		ckpt(robertLog, 2): {StatusAlreadyAnchored},
	}}
	lister := &fakeLister{pages: []s3.ListResult{
		page(ckpt(robertLog, 0), ckpt(robertLog, 2), ckpt(robertLog, 1),
			"v2/merklelog/checkpoints/14/"+robertLog+"/not-a-checkpoint.txt"),
	}}

	stats, err := newResync(pub, lister).SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Listed != 1 {
		t.Fatalf("Listed = %d, want 1 (coalesced, non-.sth skipped)", stats.Listed)
	}
	if len(pub.calls) != 1 || pub.calls[0] != ckpt(robertLog, 2) {
		t.Fatalf("calls = %v, want exactly the index-2 key", pub.calls)
	}
}

// TestSweepPaginates: keys split across truncated pages are all collected.
func TestSweepPaginates(t *testing.T) {
	p1 := page(ckpt(genesisLog, 0))
	p1.IsTruncated = true
	p1.NextContinuationToken = "t1"
	pub := &fakeSweepPub{seq: map[string][]PublishStatus{
		ckpt(genesisLog, 0): {StatusAlreadyAnchored},
		ckpt(robertLog, 0):  {StatusAlreadyAnchored},
	}}
	lister := &fakeLister{pages: []s3.ListResult{p1, page(ckpt(robertLog, 0))}}

	stats, err := newResync(pub, lister).SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Listed != 2 || lister.calls != 2 {
		t.Fatalf("Listed=%d listerCalls=%d, want 2/2", stats.Listed, lister.calls)
	}
}

// TestSweepUnresolvableOwnerBoundsPasses: an owner that never anchors leaves
// its child Blocked without spinning extra passes once progress stops.
func TestSweepUnresolvableOwnerBoundsPasses(t *testing.T) {
	pub := &fakeSweepPub{seq: map[string][]PublishStatus{
		ckpt(genesisLog, 0): {StatusPublished, StatusAlreadyAnchored},
		ckpt(childLog, 0):   {StatusOwnerNotAnchored},
	}}
	lister := &fakeLister{pages: []s3.ListResult{page(ckpt(genesisLog, 0), ckpt(childLog, 0))}}

	stats, err := newResync(pub, lister).SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Gaps != 1 || stats.Blocked != 1 {
		t.Fatalf("stats = %+v, want gaps=1 blocked=1", stats)
	}
	// pass 1: both keys; pass 2: child only (genesis settled); pass 3 never
	// runs (no progress in pass 2).
	if len(pub.calls) != 3 {
		t.Fatalf("Publish called %d times (%v), want 3", len(pub.calls), pub.calls)
	}
}
