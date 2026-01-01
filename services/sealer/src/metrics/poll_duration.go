package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// newPollDuration creates the sealer_poll_duration_seconds histogram.
func newPollDuration() prometheus.Histogram {
	return prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sealer_poll_duration_seconds",
			Help:    "Duration of poll cycles in seconds.",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		},
	)
}
