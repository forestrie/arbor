package metrics

import "github.com/prometheus/client_golang/prometheus"

// newPollsTotal creates the ranger_ingress_polls_total counter.
// Labels: result = "empty" | "partial" | "full"
func newPollsTotal() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ranger_ingress_polls_total",
			Help: "Total number of poll cycles by result (empty, partial, full).",
		},
		[]string{"result"},
	)
}
