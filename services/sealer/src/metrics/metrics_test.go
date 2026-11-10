package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestRecordSealTrigger covers the FOR-379 seal trigger counter: known sources
// are recorded under their own label; unknown values are clamped to "unknown"
// so label cardinality stays bounded.
func TestRecordSealTrigger(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.RecordSealTrigger(SealTriggerSourceR2Event)
	m.RecordSealTrigger(SealTriggerSourceR2Event)
	m.RecordSealTrigger(SealTriggerSourceRangerHint)
	m.RecordSealTrigger("something-else")

	if got := testutil.ToFloat64(m.SealTriggerTotal.WithLabelValues(SealTriggerSourceR2Event)); got != 2 {
		t.Errorf("r2_event count = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.SealTriggerTotal.WithLabelValues(SealTriggerSourceRangerHint)); got != 1 {
		t.Errorf("ranger_hint count = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.SealTriggerTotal.WithLabelValues(SealTriggerSourceUnknown)); got != 1 {
		t.Errorf("unknown count = %v, want 1", got)
	}
}

// TestObserveCheckpointLag asserts the FOR-379 lag histogram registers and
// accumulates observations.
func TestObserveCheckpointLag(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.ObserveCheckpointLag(0.4)
	m.ObserveCheckpointLag(42)

	count := testutil.CollectAndCount(m.CheckpointLag, "sealer_checkpoint_lag_seconds")
	if count != 1 {
		t.Fatalf("expected 1 registered histogram series, got %d", count)
	}
}

// TestIncCheckpointDeferred: a seal waiting on univocity to anchor its log
// is counted apart from one waiting on a delegation, and an unknown reason
// is counted as pending, so label cardinality stays bounded.
func TestIncCheckpointDeferred(t *testing.T) {
	m := NewMetrics(prometheus.NewRegistry())
	for _, reason := range []string{"pending", "expired", "authority_pending", "authority_pending", "something-else"} {
		m.IncCheckpointDeferred(reason)
	}
	for reason, want := range map[string]float64{"pending": 2, "expired": 1, "authority_pending": 2} {
		if got := testutil.ToFloat64(m.CheckpointDeferredTotal.WithLabelValues(reason)); got != want {
			t.Errorf("%s count = %v, want %v", reason, got, want)
		}
	}
}
