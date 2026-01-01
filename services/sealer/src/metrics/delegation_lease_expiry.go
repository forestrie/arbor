package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// newDelegationLeaseExpiry creates the sealer_delegation_lease_expiry_seconds gauge.
// This tracks the Unix timestamp when the current delegation lease expires,
// enabling alerting on lease renewal issues.
func newDelegationLeaseExpiry() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "sealer_delegation_lease_expiry_seconds",
			Help: "Unix timestamp when the delegation lease expires.",
		},
	)
}
