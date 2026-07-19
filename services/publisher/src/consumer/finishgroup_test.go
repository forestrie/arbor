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

	"github.com/forestrie/arbor/services/publisher"
	"github.com/forestrie/arbor/services/publisher/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// ackRecorder is an httptest queue backend that records the lease IDs acked, so
// a test can assert exactly which messages finishGroup consumed.
func ackRecorder(t *testing.T) (*QueueConsumer, func() []string) {
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
		cfg:        publisher.Config{QueueURL: srv.URL + "/messages", QueueToken: "t"},
		httpClient: publisher.NewHTTPClient(discard),
		logger:     discard,
		metrics:    metrics.NewMetrics(prometheus.NewRegistry()),
	}
	return q, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), acked...)
	}
}

func has(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

func group() logGroup {
	return logGroup{
		primary:  QueueMessage{ID: "p", LeaseID: "lease-p"},
		key:      ckKey("70717273-7475-4677-a879-7a7b7c7d7e7f", 2),
		siblings: []QueueMessage{{ID: "s0", LeaseID: "lease-s0"}, {ID: "s1", LeaseID: "lease-s1"}},
	}
}

// TestFinishGroupOwnerGatedRedeliversWithoutResync: with the sweep disabled
// (ResyncInterval 0), owner_not_anchored keeps the pre-plan-2607-07 contract —
// nothing acked, redelivery reconciles.
func TestFinishGroupOwnerGatedRedeliversWithoutResync(t *testing.T) {
	q, acked := ackRecorder(t)
	q.finishGroup(context.Background(), group(), publisher.PublishResult{Status: publisher.StatusOwnerNotAnchored})
	if got := acked(); len(got) != 0 {
		t.Fatalf("acked %v, want none (redelivery owns reconciliation when resync is off)", got)
	}
}

// TestFinishGroupOwnerGatedAcksUnderResync: with RESYNC_INTERVAL set the sweep
// owns reconciliation, so an owner-gated primary and its subsumed siblings are
// acked instead of marching to the retry cliff (plan-2607-07 R2 / FOR-408).
func TestFinishGroupOwnerGatedAcksUnderResync(t *testing.T) {
	q, acked := ackRecorder(t)
	q.cfg.ResyncInterval = time.Minute
	q.finishGroup(context.Background(), group(), publisher.PublishResult{Status: publisher.StatusOwnerNotAnchored})
	got := acked()
	for _, lease := range []string{"lease-p", "lease-s0", "lease-s1"} {
		if !has(got, lease) {
			t.Fatalf("acked %v, missing %s", got, lease)
		}
	}
}

// TestFinishGroupUnpublishableDoesNotAckSiblings: on an unpublishable primary
// (StatusReverted) the primary is terminally acked but the lower-massif siblings
// are NOT — a lower seal is not necessarily unpublishable, so it must be left to
// redeliver and be adjudicated on its own (adr-0008 self-heal, no silent drop).
func TestFinishGroupUnpublishableDoesNotAckSiblings(t *testing.T) {
	q, acked := ackRecorder(t)
	q.finishGroup(context.Background(), group(), publisher.PublishResult{Status: publisher.StatusReverted})
	got := acked()
	if !has(got, "lease-p") {
		t.Errorf("unpublishable primary should be acked; acked=%v", got)
	}
	if has(got, "lease-s0") || has(got, "lease-s1") {
		t.Errorf("siblings must NOT be acked on an unpublishable primary; acked=%v", got)
	}
}

// TestFinishGroupPublishedAcksSiblings: when the primary actually anchors, the
// subsumed siblings are acked too (covered by the anchored seal's consistency
// chain).
func TestFinishGroupPublishedAcksSiblings(t *testing.T) {
	q, acked := ackRecorder(t)
	q.finishGroup(context.Background(), group(), publisher.PublishResult{Status: publisher.StatusPublished})
	got := acked()
	for _, lease := range []string{"lease-p", "lease-s0", "lease-s1"} {
		if !has(got, lease) {
			t.Errorf("published primary should ack primary+siblings; missing %s; acked=%v", lease, got)
		}
	}
}
