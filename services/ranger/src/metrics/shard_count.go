package metrics

import "github.com/prometheus/client_golang/prometheus"

// newShardCount creates the ranger_ingress_shard_count gauge.
func newShardCount() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ranger_ingress_shard_count",
			Help: "Number of shards ranger is currently polling.",
		},
	)
}
