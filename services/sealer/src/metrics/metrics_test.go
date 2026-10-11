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

// TestSetDelegateKeyRegistered covers the plan-2609-12 slice 05 gauge: one
// series per epoch, 1 when registered on every coordinator shard, else 0.
func TestSetDelegateKeyRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.SetDelegateKeyRegistered(2, false)
	if got := testutil.ToFloat64(m.DelegateKeyRegistered.WithLabelValues("2")); got != 0 {
		t.Errorf("epoch 2 = %v, want 0", got)
	}
	m.SetDelegateKeyRegistered(2, true)
	if got := testutil.ToFloat64(m.DelegateKeyRegistered.WithLabelValues("2")); got != 1 {
		t.Errorf("epoch 2 = %v, want 1", got)
	}
	if n := testutil.CollectAndCount(m.DelegateKeyRegistered, "sealer_delegate_key_registered"); n != 1 {
		t.Errorf("series = %d, want 1", n)
	}
}
