package consumer

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/publisher"
	"github.com/forestrie/arbor/services/publisher/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// fakePub implements publishCore. Each key reports owner_not_anchored until it
// has been assembled readyAfter[key] times, then reports ready — modelling an
// owner (authority log) that anchors mid-drain after a few polls. readyAfter 0
// means ready on the first assemble (owner already anchored, cross-batch).
type fakePub struct {
	mu         sync.Mutex
	readyAfter map[string]int
	calls      map[string]int
	submitted  []string // keys handed to SubmitBatch
}

func newFakePub() *fakePub {
	return &fakePub{readyAfter: map[string]int{}, calls: map[string]int{}}
}

func (f *fakePub) From() common.Address { return common.Address{} }

func (f *fakePub) Assemble(_ context.Context, key string) ([]byte, publisher.PublishResult, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[key]++
	if f.calls[key] > f.readyAfter[key] {
		return []byte("calldata"),
			publisher.PublishResult{Status: publisher.StatusPublished, Key: key},
			true, nil
	}
	return nil,
		publisher.PublishResult{Status: publisher.StatusOwnerNotAnchored, Key: key},
		false, nil
}

func (f *fakePub) SubmitBatch(_ context.Context, reqs []publisher.AssembledPublish) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for range reqs {
		f.submitted = append(f.submitted, "submitted")
	}
}

func (f *fakePub) submittedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.submitted)
}

func (f *fakePub) assembleCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[key]
}

// drainConsumer builds a QueueConsumer wired to a fake publishCore and an
// httptest queue backend that records acks, with the given drain config.
func drainConsumer(t *testing.T, pub publishCore, ownerWait, ownerPoll time.Duration) (*QueueConsumer, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var acked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Acks []struct {
				LeaseID string `json:"lease_id"`
			} `json:"acks"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		for _, a := range body.Acks {
			acked = append(acked, a.LeaseID)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"result":{"ackCount":1,"retryCount":0},"errors":[]}`)
	}))
	t.Cleanup(srv.Close)

	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	q := &QueueConsumer{
		cfg: publisher.Config{
			QueueURL:   srv.URL + "/messages",
			QueueToken: "t",
			OwnerWait:  ownerWait,
			OwnerPoll:  ownerPoll,
		},
		httpClient: publisher.NewHTTPClient(discard),
		logger:     discard,
		pub:        pub,
		metrics:    metrics.NewMetrics(prometheus.NewRegistry()),
	}
	return q, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), acked...)
	}
}

func deferredOf(key, lease string) deferredGroup {
	return deferredGroup{
		g:   logGroup{primary: QueueMessage{ID: "p", LeaseID: lease}, key: key},
		res: publisher.PublishResult{Status: publisher.StatusOwnerNotAnchored, Key: key},
	}
}

// TestDrain_OwnerAnchorsMidDrain_Submits is the FOR-395 regression: a child held
// as owner_not_anchored is re-assembled and submitted once its owner anchors,
// instead of being released to a full-visibility-timeout redelivery.
func TestDrain_OwnerAnchorsMidDrain_Submits(t *testing.T) {
	key := ckKey("70717273-7475-4677-a879-7a7b7c7d7e7f", 0)
	pub := newFakePub()
	pub.readyAfter[key] = 2 // ready on the 3rd assemble

	q, acked := drainConsumer(t, pub, 2*time.Second, 1*time.Millisecond)
	q.drainDeferred(context.Background(), []deferredGroup{deferredOf(key, "lease-child")})

	if pub.submittedCount() != 1 {
		t.Fatalf("child should be submitted once its owner anchors; submitted=%d", pub.submittedCount())
	}
	if has(acked(), "lease-child") {
		t.Errorf("a submitted child is acked async by the collector, not by the drain release path")
	}
	if pub.assembleCount(key) < 3 {
		t.Errorf("expected the drain to re-assemble until ready (>=3); got %d", pub.assembleCount(key))
	}
}

// TestDrain_OwnerNeverAnchors_ReleasesForRedelivery: when the owner never
// anchors within OwnerWait, the group is released (owner_not_anchored, not
// acked) so it redelivers — the pre-FOR-395 slow path, budget untouched.
func TestDrain_OwnerNeverAnchors_ReleasesForRedelivery(t *testing.T) {
	key := ckKey("80717273-7475-4677-a879-7a7b7c7d7e7f", 0)
	pub := newFakePub()
	pub.readyAfter[key] = 1 << 30 // never ready

	q, acked := drainConsumer(t, pub, 20*time.Millisecond, 2*time.Millisecond)
	q.drainDeferred(context.Background(), []deferredGroup{deferredOf(key, "lease-stuck")})

	if pub.submittedCount() != 0 {
		t.Errorf("a never-anchoring owner must not be submitted; submitted=%d", pub.submittedCount())
	}
	if has(acked(), "lease-stuck") {
		t.Errorf("owner_not_anchored must NOT be acked — it redelivers; acked=%v", acked())
	}
}

// TestDrain_PollLongerThanWait_DoesNotOvershoot (F1 regression): a poll interval
// longer than OwnerWait must not hold the message past OwnerWait — otherwise a
// misconfigured OwnerPoll could keep a message in flight past its lease and the
// queue would redeliver it, duplicating the publish. The per-iteration sleep is
// capped to the remaining budget.
func TestDrain_PollLongerThanWait_DoesNotOvershoot(t *testing.T) {
	key := ckKey("a0717273-7475-4677-a879-7a7b7c7d7e7f", 0)
	pub := newFakePub()
	pub.readyAfter[key] = 1 << 30 // never anchors

	// OwnerPoll (1s) >> OwnerWait (20ms): without the deadline cap the drain
	// would sleep ~1s.
	q, acked := drainConsumer(t, pub, 20*time.Millisecond, 1*time.Second)
	start := time.Now()
	q.drainDeferred(context.Background(), []deferredGroup{deferredOf(key, "lease-z")})
	held := time.Since(start)

	if held > 250*time.Millisecond {
		t.Errorf("drain held %s, must be bounded by OwnerWait (20ms) not OwnerPoll (1s)", held)
	}
	if has(acked(), "lease-z") {
		t.Errorf("timed-out group must not be acked; acked=%v", acked())
	}
}

// TestDrain_DisabledWhenOwnerWaitZero_ReleasesImmediately: OwnerWait == 0
// disables the drain; deferred groups are released at once (no re-assembly).
func TestDrain_DisabledWhenOwnerWaitZero_ReleasesImmediately(t *testing.T) {
	key := ckKey("90717273-7475-4677-a879-7a7b7c7d7e7f", 0)
	pub := newFakePub()
	pub.readyAfter[key] = 0 // would be ready immediately IF re-assembled

	q, acked := drainConsumer(t, pub, 0, 1*time.Millisecond)
	q.drainDeferred(context.Background(), []deferredGroup{deferredOf(key, "lease-x")})

	if pub.assembleCount(key) != 0 {
		t.Errorf("drain disabled: no re-assembly expected; got %d", pub.assembleCount(key))
	}
	if pub.submittedCount() != 0 {
		t.Errorf("drain disabled: nothing submitted; submitted=%d", pub.submittedCount())
	}
	if has(acked(), "lease-x") {
		t.Errorf("owner_not_anchored release must not ack; acked=%v", acked())
	}
}
