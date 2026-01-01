package metrics

import "github.com/prometheus/client_golang/prometheus"

// newEntriesPerPoll creates the ranger_ingress_entries_per_poll histogram.
func newEntriesPerPoll() prometheus.Histogram {
	return prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ranger_ingress_entries_per_poll",
			Help:    "Distribution of entries returned per poll.",
			Buckets: []float64{0, 1, 5, 10, 25, 50, 75, 100, 150, 200},
		},
	)
}
