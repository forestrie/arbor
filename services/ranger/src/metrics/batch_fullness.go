package metrics

import "github.com/prometheus/client_golang/prometheus"

// newBatchFullnessRatio creates the ranger_ingress_batch_fullness_ratio gauge.
func newBatchFullnessRatio() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ranger_ingress_batch_fullness_ratio",
			Help: "Most recent batch fullness as a ratio (0.0 to 1.0), entries returned divided by batch size.",
		},
	)
}
