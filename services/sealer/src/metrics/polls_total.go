package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// newPollsTotal creates the sealer_polls_total counter.
// Labels: result (empty|success|failure)
func newPollsTotal() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sealer_polls_total",
			Help: "Total number of queue polls by result.",
		},
		[]string{"result"},
	)
}
