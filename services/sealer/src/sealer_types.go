package sealer

import "log/slog"

// SealerService holds dependencies known at service startup time.
type SealerService struct {
	Cfg          Config
	HTTPClient   *HTTPClient
	Logger       *slog.Logger
	LeaseManager *DelegationLeaseManager
}

// SealerBatch holds values known when a batch of messages is received.
type SealerBatch struct {
	DelegationAccessToken string
}


