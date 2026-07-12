package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// newCheckpointLag creates the sealer_checkpoint_lag_seconds histogram.
//
// Lag is measured from the massif's last entry idtimestamp to the checkpoint
// write time — the end-to-end trigger latency ADR-0007 targets. Buckets span
// the sub-second wake we are aiming for (phase 2 long-poll) up to the
// tens-of-seconds R2 event-notification delays observed today, with headroom
// for idle-lane worst cases.
func newCheckpointLag() prometheus.Histogram {
	return prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sealer_checkpoint_lag_seconds",
			Help:    "Seconds from the massif's last entry idtimestamp to the checkpoint write (ADR-0007 trigger latency).",
			Buckets: []float64{0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300, 600},
		},
	)
}
