package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestSetDelegateKeyRegistered covers the plan-2609-12 slice 05 gauge: one
// series per held epoch, 1 while that key's assertion is current, else 0.
func TestSetDelegateKeyRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.SetDelegateKeyRegistered(2, false)
	if got := testutil.ToFloat64(m.DelegateKeyRegistered.WithLabelValues("2")); got != 0 {
		t.Errorf("epoch 2 = %v, want 0", got)
	}
	m.SetDelegateKeyRegistered(2, true)
	m.SetDelegateKeyRegistered(1, false)
	if got := testutil.ToFloat64(m.DelegateKeyRegistered.WithLabelValues("2")); got != 1 {
		t.Errorf("epoch 2 = %v, want 1", got)
	}
	if n := testutil.CollectAndCount(m.DelegateKeyRegistered, "sealer_delegate_key_registered"); n != 2 {
		t.Errorf("series = %d, want 2", n)
	}
	m.DeleteDelegateKeyRegistered(1)
	if n := testutil.CollectAndCount(m.DelegateKeyRegistered, "sealer_delegate_key_registered"); n != 1 {
		t.Errorf("series after delete = %d, want 1", n)
	}
}
