package consumer

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/forestrie/arbor/services/sealer/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const testMassifKey = "v2/merklelog/massifs/14/3062ea57-c184-41d8-bd61-296b02c680d8/0000000000000000.log"

// queueMessage builds a QueueMessage the way the Cloudflare Queues pull
// delivers it: the message body is a JSON string token containing the
// notification JSON (hence the double marshal).
func queueMessage(t *testing.T, id string, note R2Notification) QueueMessage {
	t.Helper()
	inner, err := json.Marshal(note)
	if err != nil {
		t.Fatalf("marshal notification: %v", err)
	}
	body, err := json.Marshal(string(inner))
	if err != nil {
		t.Fatalf("marshal body wrapper: %v", err)
	}
	return QueueMessage{ID: id, Body: body, LeaseID: "lease-" + id}
}

func newGroupingConsumer(t *testing.T) (*QueueConsumer, *metrics.Metrics) {
	t.Helper()
	m := metrics.NewMetrics(prometheus.NewRegistry())
	return &QueueConsumer{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics: m,
	}, m
}

// TestGroupLogWorkDedupesHintAndR2Event asserts the ADR-0007 phase 1 dedupe
// property: a ranger seal hint and the R2 event notification for the SAME
// massif object key coalesce into one logWork group — CheckpointLog runs once
// per log per batch and re-derives its work from R2 state, so the duplicate
// trigger is harmless by construction. Both wake paths are still attributed
// separately in sealer_seal_trigger_total.
func TestGroupLogWorkDedupesHintAndR2Event(t *testing.T) {
	q, m := newGroupingConsumer(t)

	r2Event := queueMessage(t, "m1", R2Notification{
		Action: "PutObject",
		Object: R2Object{Key: testMassifKey},
	})
	rangerHint := queueMessage(t, "m2", R2Notification{
		Action:     "PutObject",
		Object:     R2Object{Key: testMassifKey},
		HintSource: metrics.SealTriggerSourceRangerHint,
	})

	unique, invalid := q.groupLogWork([]QueueMessage{r2Event, rangerHint})

	if len(invalid) != 0 {
		t.Fatalf("invalid = %d, want 0", len(invalid))
	}
	if len(unique) != 1 {
		t.Fatalf("groups = %d, want 1 (hint + event for the same massif must coalesce)", len(unique))
	}
	for _, w := range unique {
		if len(w.messages) != 2 {
			t.Errorf("group messages = %d, want 2 (both acked when the single checkpoint succeeds)", len(w.messages))
		}
		if w.massifHeight != 14 {
			t.Errorf("massifHeight = %d, want 14", w.massifHeight)
		}
	}

	if got := testutil.ToFloat64(m.SealTriggerTotal.WithLabelValues(metrics.SealTriggerSourceR2Event)); got != 1 {
		t.Errorf("r2_event triggers = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.SealTriggerTotal.WithLabelValues(metrics.SealTriggerSourceRangerHint)); got != 1 {
		t.Errorf("ranger_hint triggers = %v, want 1", got)
	}
}

// TestGroupLogWorkClampsUnknownHintSource keeps trigger label cardinality
// bounded when a future/misconfigured producer marks an unrecognised source.
func TestGroupLogWorkClampsUnknownHintSource(t *testing.T) {
	q, m := newGroupingConsumer(t)

	msg := queueMessage(t, "m1", R2Notification{
		Action:     "PutObject",
		Object:     R2Object{Key: testMassifKey},
		HintSource: "some-future-source",
	})

	unique, invalid := q.groupLogWork([]QueueMessage{msg})
	if len(invalid) != 0 || len(unique) != 1 {
		t.Fatalf("unique=%d invalid=%d, want 1/0", len(unique), len(invalid))
	}
	if got := testutil.ToFloat64(m.SealTriggerTotal.WithLabelValues(metrics.SealTriggerSourceUnknown)); got != 1 {
		t.Errorf("unknown triggers = %v, want 1", got)
	}
}

// TestGroupLogWorkRejectsNonPutObject documents the action gate a seal hint
// must satisfy (the ranger publisher sets Action "PutObject" for exactly this
// reason).
func TestGroupLogWorkRejectsNonPutObject(t *testing.T) {
	q, _ := newGroupingConsumer(t)

	msg := queueMessage(t, "m1", R2Notification{
		Action: "DeleteObject",
		Object: R2Object{Key: testMassifKey},
	})

	unique, invalid := q.groupLogWork([]QueueMessage{msg})
	if len(unique) != 0 {
		t.Errorf("groups = %d, want 0", len(unique))
	}
	if len(invalid) != 1 {
		t.Errorf("invalid = %d, want 1 (acked so it cannot poison the queue)", len(invalid))
	}
}
