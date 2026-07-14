package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// newCheckpointDeferredTotal creates the sealer_checkpoint_deferred_total counter.
// Incremented whenever a log's checkpoint is deferred (message intentionally not
// acked, awaiting queue redelivery) because its delegation is not yet usable.
// Labels: reason (pending|expired) — "pending" = no covering delegation
// certificate is available yet (BYOK/advance not pre-submitted); "expired" = the
// cached lease has expired or is expiring.
//
// This is the primary operator signal that seals are stuck on delegation: it
// (and the paired WARN log) surfaces the condition that is otherwise invisible
// at the deployed "notice" log level.
func newCheckpointDeferredTotal() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sealer_checkpoint_deferred_total",
			Help: "Total checkpoints deferred awaiting a usable delegation, by reason.",
		},
		[]string{"reason"},
	)
}
