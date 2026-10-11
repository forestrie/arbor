package metrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// newDelegateKeyRegistered creates the sealer_delegate_key_registered gauge
// (devdocs plan-2609-12 slice 05, ruling 1). 1 when the coordinator's lookup
// (GET /api/sealer/delegate-keys/{pubkeyHash}, canopy delegation-coordinator)
// reports the sealer's current standing delegate key registered on every
// shard; 0 when it reports the key missing or partially registered. Label:
// epoch (the sealer's DELEGATE_KEY_EPOCH).
//
// This is the operator signal for registration, replacing log reading: alert
// on sealer_delegate_key_registered == 0 for 15 min.
func newDelegateKeyRegistered() *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sealer_delegate_key_registered",
			Help: "1 when the current standing delegate key is registered on every coordinator shard, else 0.",
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
