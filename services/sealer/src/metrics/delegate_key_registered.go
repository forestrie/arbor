package metrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// newDelegateKeyRegistered creates the sealer_delegate_key_registered gauge
// (devdocs plan-2609-12 slice 05 change 5): one series per held epoch, 1
// while the last successful assertion of that epoch's key (POST
// /api/sealer/delegate-keys) is under 5 min old, else 0. The operator alert
// is sealer_delegate_key_registered == 0 for 15 min (arbor-flux).
func newDelegateKeyRegistered() *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sealer_delegate_key_registered",
			Help: "1 while the coordinator accepted an assertion of this epoch's standing delegate key in the last 5 min, else 0.",
		},
		[]string{"epoch"},
	)
}

// SetDelegateKeyRegistered sets sealer_delegate_key_registered for epoch.
func (m *Metrics) SetDelegateKeyRegistered(epoch uint32, registered bool) {
	v := 0.0
	if registered {
		v = 1
	}
	m.DelegateKeyRegistered.WithLabelValues(strconv.FormatUint(uint64(epoch), 10)).Set(v)
}
