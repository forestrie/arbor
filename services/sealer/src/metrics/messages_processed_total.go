package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// newMessagesProcessedTotal creates the sealer_messages_processed_total counter.
func newMessagesProcessedTotal() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sealer_messages_processed_total",
			Help: "Total number of queue messages processed.",
		},
	)
}
