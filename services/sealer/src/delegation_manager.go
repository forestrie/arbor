package sealer

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

const (
	// defaultDelegationTTL is the lifetime requested for delegation certificates.
	defaultDelegationTTL = 60 * time.Minute
	// defaultRenewBefore is the minimum remaining lifetime required to start a
	// log checkpointing run. If remaining < defaultRenewBefore, sealer renews
	// before starting.
	defaultRenewBefore = 5 * time.Minute
	// defaultMaxLeases is the maximum number of per-log leases to cache.
	defaultMaxLeases = 1000
)

// leaseEntry wraps a lease with its key for LRU eviction.
type leaseEntry struct {
	key   string
	lease *DelegationLease
}

type pendingKeyEntry struct {
	keyPair   *DelegatedKeyPair
	createdAt time.Time
}

// DelegationLeaseManager manages per-log, time-limited delegation leases
// for the sealer process. Uses LRU eviction when the cache is full.
type DelegationLeaseManager struct {
	trustRoot   TrustRootClient
	authorizer  AuthorizeClient
	issuer      DelegationIssuer
	mu          sync.Mutex
	leases      map[string]*list.Element // logIdHex -> list element
	pendingKeys map[string]*pendingKeyEntry
	lru         *list.List // LRU order (front = most recent)
	maxLeases   int
	ttl         time.Duration
	renewBefore time.Duration
}

func NewDelegationLeaseManager(
	trustRoot TrustRootClient,
	issuer DelegationIssuer,
	ttl, renewBefore time.Duration,
) *DelegationLeaseManager {
	if ttl <= 0 {
		ttl = defaultDelegationTTL
	}
	if renewBefore <= 0 {
		renewBefore = defaultRenewBefore
	}
	return &DelegationLeaseManager{
		trustRoot:   trustRoot,
		issuer:      issuer,
		leases:      make(map[string]*list.Element),
		pendingKeys: make(map[string]*pendingKeyEntry),
		lru:         list.New(),
		maxLeases:   defaultMaxLeases,
		ttl:         ttl,
		renewBefore: renewBefore,
	}
}

// SetAuthorizer enables the trusted univocity authorize path. When set, the
// manager resolves a log's root key (and chain binding) from the certificate
// via univocity rather than the legacy trust-root-by-logId lookup.
func (m *DelegationLeaseManager) SetAuthorizer(a AuthorizeClient) {
	m.authorizer = a
}

// EnsureValidForLog returns a delegation lease for a specific log that is not
// expired and has at least renewBefore remaining lifetime. If no such lease
// exists, it requests a new one from the delegation issuer and verifies it
// against the trust root before caching.
func (m *DelegationLeaseManager) EnsureValidForLog(
	ctx context.Context,
	httpClient *HTTPClient,
	logger *slog.Logger,
	curve string,
	logIdHex string,
	mmrStart, mmrEnd uint64,
) (*DelegationLease, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if m.issuer == nil || (m.trustRoot == nil && m.authorizer == nil) {
		return nil, fmt.Errorf("delegation seams not configured")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()

	// Check for existing valid lease
	if elem, ok := m.leases[logIdHex]; ok {
		entry := elem.Value.(*leaseEntry)
		lease := entry.lease
		remaining := time.Until(lease.ExpiresAt)
		if remaining >= m.renewBefore && now.Before(lease.ExpiresAt) {
			// Move to front (most recently used)
			m.lru.MoveToFront(elem)
			return lease, nil
		}
		// Expired or expiring soon - remove it
		m.lru.Remove(elem)
		delete(m.leases, logIdHex)
	}

	keyPair, err := m.pendingKeyForLogLocked(curve, logIdHex, now)
	if err != nil {
		return nil, err
	}

	lease, err := requestLogDelegationLeaseWithKeyPair(
		ctx, httpClient, m.trustRoot, m.authorizer, m.issuer, curve, m.ttl,
		logIdHex, mmrStart, mmrEnd, keyPair,
	)
	if err != nil {
		if !errors.Is(err, ErrDelegationPending) {
			delete(m.pendingKeys, logIdHex)
		}
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

	logger.Info("obtained per-log delegation lease",
		"log_id", logIdHex,
		"cert_sha256", lease.Info.CertSHA256,
		"alg", lease.Info.ProtectedAlg,
		"kid_hex", lease.Info.ProtectedKidHex,
		"issued_at", lease.IssuedAt.Format(time.RFC3339),
		"expires_at", lease.ExpiresAt.Format(time.RFC3339),
		"ttl", m.ttl.String(),
		"renew_before", m.renewBefore.String(),
	)

	// Evict oldest if at capacity
	if m.lru.Len() >= m.maxLeases {
		oldest := m.lru.Back()
		if oldest != nil {
			oldEntry := oldest.Value.(*leaseEntry)
			m.lru.Remove(oldest)
			delete(m.leases, oldEntry.key)
			logger.Debug("evicted oldest delegation lease", "evicted_log_id", oldEntry.key)
		}
	}

	// Add new lease to cache
	entry := &leaseEntry{key: logIdHex, lease: lease}
	elem := m.lru.PushFront(entry)
	m.leases[logIdHex] = elem
	delete(m.pendingKeys, logIdHex)

	return lease, nil
}

func (m *DelegationLeaseManager) RenewBefore() time.Duration {
	return m.renewBefore
}

func (m *DelegationLeaseManager) pendingKeyForLogLocked(
	curveRaw string,
	logIdHex string,
	now time.Time,
) (*DelegatedKeyPair, error) {
	if entry, ok := m.pendingKeys[logIdHex]; ok {
		if now.Sub(entry.createdAt) < m.ttl {
			return entry.keyPair, nil
		}
		delete(m.pendingKeys, logIdHex)
	}

	curve, err := delegationcert.ParseCurve(curveRaw)
	if err != nil {
		return nil, err
	}
	priv, pub, err := generateEphemeralKey(curve)
	if err != nil {
		return nil, err
	}
	keyPair := &DelegatedKeyPair{Private: priv, Public: pub}
	m.pendingKeys[logIdHex] = &pendingKeyEntry{
		keyPair:   keyPair,
		createdAt: now,
	}
	return keyPair, nil
}

// NOTE: We intentionally avoid package-level global state. Construct a
// DelegationLeaseManager at service startup and pass it through call-sites.
