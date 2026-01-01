package metrics

import "github.com/prometheus/client_golang/prometheus"

// newAcksTotal creates the ranger_ingress_acks_total counter.
// Labels: status = "success" | "failure"
func newAcksTotal() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ranger_ingress_acks_total",
			Help: "Total number of acknowledgement attempts by status (success, failure).",
		},
		[]string{"status"},
	)
}
