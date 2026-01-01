package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// newCheckpointDuration creates the sealer_checkpoint_duration_seconds histogram.
// Buckets span from 100ms to 60s to capture checkpoint operations including
// signing and R2 writes.
func newCheckpointDuration() prometheus.Histogram {
	return prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sealer_checkpoint_duration_seconds",
			Help:    "Duration of checkpoint operations in seconds.",
			Buckets: []float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60},
		},
	)
}
