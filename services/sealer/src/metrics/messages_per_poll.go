package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// newMessagesPerPoll creates the sealer_messages_per_poll histogram.
// Buckets optimized for sealer's lower message volumes.
func newMessagesPerPoll() prometheus.Histogram {
	return prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sealer_messages_per_poll",
			Help:    "Distribution of messages returned per poll.",
			Buckets: []float64{0, 1, 2, 4, 8, 16, 32},
		},
	)
}
