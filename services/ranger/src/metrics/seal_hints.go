package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// newSealHintsPublishedTotal creates the ranger_seal_hints_published_total counter.
func newSealHintsPublishedTotal() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ranger_seal_hints_published_total",
			Help: "Total seal hints successfully published to the sealer queue (ADR-0007 phase 1).",
		},
	)
}

// newSealHintPublishFailuresTotal creates the ranger_seal_hint_publish_failures_total counter.
//
// Failures are fire-and-forget: they never block or fail the commit path. The
// R2 event-notification backstop still wakes the sealer, so a raised failure
// rate here degrades latency, not correctness.
func newSealHintPublishFailuresTotal() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ranger_seal_hint_publish_failures_total",
			Help: "Total seal hint publishes that failed after retries (ADR-0007 phase 1; latency degradation only, R2 events backstop).",
		},
	)
}
