package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// newMessagesAcknowledgedTotal creates the sealer_messages_acknowledged_total counter.
// Labels: status (success|failure)
func newMessagesAcknowledgedTotal() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sealer_messages_acknowledged_total",
			Help: "Total number of message acknowledgments by status.",
		},
		[]string{"status"},
	)
}
