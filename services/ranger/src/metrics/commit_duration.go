package metrics

import "github.com/prometheus/client_golang/prometheus"

// newCommitDuration creates the ranger_ingress_commit_duration_seconds histogram.
func newCommitDuration() prometheus.Histogram {
	return prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ranger_ingress_commit_duration_seconds",
			Help:    "Duration of R2 commit operations.",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
	)
}
