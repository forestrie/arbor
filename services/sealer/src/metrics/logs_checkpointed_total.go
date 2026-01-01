package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// newLogsCheckpointedTotal creates the sealer_logs_checkpointed_total counter.
func newLogsCheckpointedTotal() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sealer_logs_checkpointed_total",
			Help: "Total number of logs successfully checkpointed.",
		},
	)
}
