package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Known seal trigger sources (ADR-0007). The label set is fixed here so the
// series cardinality stays bounded; later phases extend the wake paths:
//   - r2_event: R2 PutObject event notification (the only source today)
//   - ranger_hint: ranger-published seal hint into the sealer queue (phase 1)
//   - long_poll: seal-coordinator long-poll wake (phase 2)
//   - sweep: periodic unsealed-head sweep (phase 3)
//   - unknown: a hint-marked message with an unrecognised source value
const (
	SealTriggerSourceR2Event    = "r2_event"
	SealTriggerSourceRangerHint = "ranger_hint"
	SealTriggerSourceLongPoll   = "long_poll"
	SealTriggerSourceSweep      = "sweep"
	SealTriggerSourceUnknown    = "unknown"
)

// newSealTriggerTotal creates the sealer_seal_trigger_total counter vector.
func newSealTriggerTotal() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sealer_seal_trigger_total",
			Help: "Total seal trigger messages accepted for checkpoint work, by wake source (ADR-0007).",
		},
		[]string{"source"},
	)
}
