package sealer

import (
	"log/slog"

	"github.com/forestrie/arbor/services/sealer/metrics"
)

// SealerService holds dependencies known at service startup time.
type SealerService struct {
	Cfg          Config
	HTTPClient   *HTTPClient
	Logger       *slog.Logger
	LeaseManager *DelegationLeaseManager
	// Metrics is optional; nil disables recording (tests, ad-hoc tooling).
	Metrics *metrics.Metrics
}

// SealerBatch holds values known when a batch of messages is received.
type SealerBatch struct {
	DelegationAccessToken string
}
