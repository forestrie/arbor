package sealer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// defaultDelegationTTL is the lifetime requested for the global delegation
	// certificate.
	defaultDelegationTTL = 60 * time.Minute
	// defaultRenewBefore is the minimum remaining lifetime required to start a
	// log checkpointing run. If remaining < defaultRenewBefore, sealer renews
	// before starting.
	defaultRenewBefore = 5 * time.Minute
)

// DelegationLeaseManager manages a single global, time-limited delegation lease
// for the sealer process.
type DelegationLeaseManager struct {
	mu          sync.Mutex
	lease       *DelegationLease
	ttl         time.Duration
	renewBefore time.Duration
}

func NewDelegationLeaseManager(ttl, renewBefore time.Duration) *DelegationLeaseManager {
	if ttl <= 0 {
		ttl = defaultDelegationTTL
	}
	if renewBefore <= 0 {
		renewBefore = defaultRenewBefore
	}
	return &DelegationLeaseManager{
		ttl:         ttl,
		renewBefore: renewBefore,
	}
}

// EnsureValid returns a delegation lease that is not expired and has at least
// renewBefore remaining lifetime. If no such lease exists, it requests a new
// one from the delegation-signer.
func (m *DelegationLeaseManager) EnsureValid(
	ctx context.Context,
	httpClient *HTTPClient,
	logger *slog.Logger,
	signerBaseURL string,
	accessToken string,
	curve string,
) (*DelegationLease, error) {
	if logger == nil {
		logger = slog.Default()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	if m.lease != nil {
		remaining := time.Until(m.lease.ExpiresAt)
		if remaining >= m.renewBefore && now.Before(m.lease.ExpiresAt) {
			return m.lease, nil
		}
	}

	lease, err := RequestGlobalDelegationLease(ctx, httpClient, signerBaseURL, accessToken, curve, m.ttl)
	if err != nil {
		return nil, err
	}

	if lease.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("delegation lease missing expiry")
	}
	if !now.Before(lease.ExpiresAt) {
		return nil, fmt.Errorf("delegation lease already expired (expiresAt=%s)", lease.ExpiresAt.Format(time.RFC3339))
	}
	if rem := time.Until(lease.ExpiresAt); rem < m.renewBefore {
		return nil, fmt.Errorf("delegation lease lifetime too short (remaining=%s)", rem)
	}

	logger.Info("obtained delegation lease",
		"cert_sha256", lease.Info.CertSHA256,
		"alg", lease.Info.ProtectedAlg,
		"kid_hex", lease.Info.ProtectedKidHex,
		"issued_at", lease.IssuedAt.Format(time.RFC3339),
		"expires_at", lease.ExpiresAt.Format(time.RFC3339),
		"ttl", m.ttl.String(),
		"renew_before", m.renewBefore.String(),
	)

	m.lease = lease
	return lease, nil
}

func (m *DelegationLeaseManager) RenewBefore() time.Duration {
	return m.renewBefore
}

// NOTE: We intentionally avoid package-level global state. Construct a
// DelegationLeaseManager at service startup and pass it through call-sites.
