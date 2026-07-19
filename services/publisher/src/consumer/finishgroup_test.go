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

// TestFinishGroupOwnerGatedAcksUnderHealthyResync: with the sweep configured
// AND healthy, an owner-gated primary and its subsumed siblings are acked
// instead of marching to the retry cliff, and the primary's key is recorded
// as a handoff so the sweep's loss signal stays honest (plan-2607-08 W2).
func TestFinishGroupOwnerGatedAcksUnderHealthyResync(t *testing.T) {
	q, acked := ackRecorder(t)
	q.cfg.ResyncInterval = time.Minute
	handoffs := publisher.NewOwnerGateHandoffs()
	q.WithResync(func() bool { return true }, handoffs)
	g := group()
	q.finishGroup(context.Background(), g, publisher.PublishResult{Status: publisher.StatusOwnerNotAnchored})
	got := acked()
	for _, lease := range []string{"lease-p", "lease-s0", "lease-s1"} {
		if !has(got, lease) {
			t.Fatalf("acked %v, missing %s", got, lease)
		}
	}
	if !handoffs.Recent(g.key, time.Minute) {
		t.Fatalf("owner-gated ack must record a handoff for %s", g.key)
	}
}

// TestFinishGroupOwnerGatedRedeliversWhenResyncUnhealthy: the flag alone is
// not enough — a configured-but-failing sweep must leave the redelivery
// contract in force (plan-2607-08 F2).
func TestFinishGroupOwnerGatedRedeliversWhenResyncUnhealthy(t *testing.T) {
	q, acked := ackRecorder(t)
	q.cfg.ResyncInterval = time.Minute
	q.WithResync(func() bool { return false }, publisher.NewOwnerGateHandoffs())
	q.finishGroup(context.Background(), group(), publisher.PublishResult{Status: publisher.StatusOwnerNotAnchored})
	if got := acked(); len(got) != 0 {
		t.Fatalf("acked %v, want none while the sweep is unhealthy", got)
	}
}

// TestFinishGroupUnpublishableDoesNotAckSiblings: on an unpublishable primary
// (StatusReverted) the primary is terminally acked but the lower-massif siblings
// are NOT — a lower seal is not necessarily unpublishable, so it must be left to
// redeliver and be adjudicated on its own (adr-0008 self-heal, no silent drop).
func TestFinishGroupUnpublishableDoesNotAckSiblings(t *testing.T) {
	q, acked := ackRecorder(t)
	// OnchainSize > 0: an established log where ADR-0008's next-seal
	// catch-up premise holds — the terminal-ack contract applies.
	q.finishGroup(context.Background(), group(), publisher.PublishResult{Status: publisher.StatusReverted, OnchainSize: 3})
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

// TestFinishGroupVirginRevertNotTerminal (FOR-411): a mined revert against a
// log with NO on-chain state must never be terminally acked — a genesis has
// no next seal to catch up from. With the sweep unhealthy/absent it
// redelivers; with a healthy sweep it is acked as a recorded handoff so the
// sweep's aged poison retries own it.
func TestFinishGroupVirginRevertNotTerminal(t *testing.T) {
	q, acked := ackRecorder(t)
	q.finishGroup(context.Background(), group(), publisher.PublishResult{Status: publisher.StatusReverted, OnchainSize: 0})
	if got := acked(); len(got) != 0 {
		t.Fatalf("acked %v, want none (virgin revert must redeliver without a healthy sweep)", got)
	}
}

func TestFinishGroupVirginRevertHandsToHealthySweep(t *testing.T) {
	q, acked := ackRecorder(t)
	q.cfg.ResyncInterval = time.Minute
	handoffs := publisher.NewOwnerGateHandoffs()
	q.WithResync(func() bool { return true }, handoffs)
	g := group()
	q.finishGroup(context.Background(), g, publisher.PublishResult{Status: publisher.StatusReverted, OnchainSize: 0})
	if got := acked(); !has(got, "lease-p") {
		t.Fatalf("acked %v, want the primary handed to the sweep", got)
	}
	if !handoffs.Recent(g.key, time.Minute) {
		t.Fatalf("virgin-revert handoff must be recorded")
	}
}
