package metrics

import "github.com/prometheus/client_golang/prometheus"

// newPollDuration creates the ranger_ingress_poll_duration_seconds histogram.
func newPollDuration() prometheus.Histogram {
	return prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ranger_ingress_poll_duration_seconds",
			Help:    "Duration of poll cycles including pull, commit, and ack operations.",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
	)
}
