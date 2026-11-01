package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Resync metrics (ADR-0007 phase-3 sweep / plan-2607-04). The level-triggered
// resync is the correctness backstop to the edge-triggered queue path: proving
// it is alive and doing work is essential to trust that dropped/deferred seals
// self-heal. Reseals driven by the resync are also counted under
// sealer_seal_trigger_total{source="sweep"}; these series add resync-loop
// liveness and the freshness hit-rate.

// newResyncPagesTotal counts active-set pages fetched from the coordinator.
func newResyncPagesTotal() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sealer_resync_pages_total",
		Help: "Total active-delegation pages fetched by the resync loop.",
	})
}

// newResyncChecksTotal counts per-log freshness checks the resync performed.
func newResyncChecksTotal() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sealer_resync_checks_total",
		Help: "Total per-log freshness checks performed by the resync loop.",
	})
}

// newResyncResealsTotal counts logs the resync found behind and re-drove.
func newResyncResealsTotal() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sealer_resync_reseals_total",
		Help: "Total logs the resync loop found unsealed and re-drove via CheckpointLog.",
	})
}

// newResyncMalformedHintTotal counts active-set rows whose mmrStart or
// mmrEnd range hint was malformed. The resync treats such a hint as absent
// and still runs the authoritative check, so a non-zero rate means the
// coordinator is emitting a range shape the sealer does not read, not that
// logs go unsealed.
func newResyncMalformedHintTotal() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sealer_resync_malformed_hint_total",
		Help: "Total active-delegation rows whose mmrStart/mmrEnd hint was malformed and was treated as absent.",
	})
}

// newResyncLastPage gauges the size of the most recent active-set page.
func newResyncLastPage() prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sealer_resync_last_page_logs",
		Help: "Number of logs in the most recent active-delegation page.",
	})
}
