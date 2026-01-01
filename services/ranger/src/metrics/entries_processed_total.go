package metrics

import "github.com/prometheus/client_golang/prometheus"

// newEntriesProcessedTotal creates the ranger_ingress_entries_processed_total counter.
func newEntriesProcessedTotal() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ranger_ingress_entries_processed_total",
			Help: "Total number of entries successfully committed to R2 storage.",
		},
	)
}
