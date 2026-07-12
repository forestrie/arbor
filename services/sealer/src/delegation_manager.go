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
	resolver    AuthorityResolver
	issuer      DelegationIssuer
	erc1271     delegationcert.ERC1271Verifier
	mu          sync.Mutex
	leases      map[string]*list.Element // logIdHex -> list element
	pendingKeys map[string]*pendingKeyEntry
	lru         *list.List // LRU order (front = most recent)
	maxLeases   int
	ttl         time.Duration
	renewBefore time.Duration
	rangePad    uint64
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

// SetAuthorityResolver enables the trusted univocity authority path. When set,
// the manager resolves a log's root key (and chain binding) by logId from
// univocity (which can resolve cold logs from the grant chain) rather than the
// legacy trust-root-by-logId lookup.
func (m *DelegationLeaseManager) SetERC1271Verifier(v delegationcert.ERC1271Verifier) {
	m.erc1271 = v
}

func (m *DelegationLeaseManager) SetAuthorityResolver(a AuthorityResolver) {
	m.resolver = a
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
	if m.issuer == nil || (m.trustRoot == nil && m.resolver == nil) {
		return nil, fmt.Errorf("delegation seams not configured")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()

	// Check for existing valid lease that still covers the requested MMR range.
	// The on-chain proof (and certificate) bind [mmrStart, mmrEnd] in the root
	// signature, so a cached lease for an earlier seal (e.g. [0,1]) must not be
	// reused for a later seal (e.g. [1,3]) — that reverts
	// CheckpointIndexOutOfDelegationRange on publishCheckpoint.
	if elem, ok := m.leases[logIdHex]; ok {
		entry := elem.Value.(*leaseEntry)
		lease := entry.lease
		remaining := time.Until(lease.ExpiresAt)
		if remaining >= m.renewBefore && now.Before(lease.ExpiresAt) &&
			leaseCoversMMRRange(lease, mmrStart, mmrEnd) {
			m.lru.MoveToFront(elem)
			return lease, nil
		}
		m.lru.Remove(elem)
		delete(m.leases, logIdHex)
	}

	keyPair, err := m.pendingKeyForLogLocked(curve, logIdHex, now)
	if err != nil {
		return nil, err
	}

	// FOR-386: pad only the ISSUANCE request. The cache check above used the
	// caller's true seal window; the wider certificate issued here then covers
	// subsequent windows until the log outgrows the pad or the TTL expires.
	lease, err := requestLogDelegationLeaseWithKeyPair(
		ctx, httpClient, m.trustRoot, m.resolver, m.issuer, m.erc1271, curve, m.ttl,
		logIdHex, mmrStart, paddedRangeEnd(mmrEnd, m.rangePad), keyPair,
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

// SetMaxLeases caps the per-log lease LRU (DELEGATION_MAX_LEASES). Ignores
// non-positive values, keeping the constructor default.
func (m *DelegationLeaseManager) SetMaxLeases(n int) {
	if n > 0 {
		m.maxLeases = n
	}
}

// SetRangePad configures how far beyond the seal window delegation ISSUANCE
// requests extend (DELEGATION_RANGE_PAD; FOR-386). Cache-coverage checks are
// unaffected — they always use the caller's true window.
func (m *DelegationLeaseManager) SetRangePad(pad uint64) {
	m.rangePad = pad
}

// paddedRangeEnd widens a delegation range end by pad MMR nodes, clamping on
// uint64 overflow (FOR-386).
func paddedRangeEnd(mmrEnd, pad uint64) uint64 {
	if pad > ^uint64(0)-mmrEnd {
		return ^uint64(0)
	}
	return mmrEnd + pad
}

// leaseCoversMMRRange reports whether lease authorizes sealing through
// [mmrStart, mmrEnd] (inclusive). Prefers the on-chain proof bounds (what
// univocity checks); falls back to the COSE certificate payload when the
// issuer omitted onchainProof.
func leaseCoversMMRRange(lease *DelegationLease, mmrStart, mmrEnd uint64) bool {
	if lease == nil {
		return false
	}
	if lease.OnchainProof != nil {
		return lease.OnchainProof.MMRStart <= mmrStart &&
			lease.OnchainProof.MMREnd >= mmrEnd
	}
	if lease.Info == nil {
		return false
	}
	start, errStart := parseUint64Decimal(lease.Info.PayloadMmrStart)
	end, errEnd := parseUint64Decimal(lease.Info.PayloadMmrEnd)
	if errStart != nil || errEnd != nil {
		return false
	}
	return start <= mmrStart && end >= mmrEnd
}

func parseUint64Decimal(s string) (uint64, error) {
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-decimal mmr bound %q", s)
		}
		v = v*10 + uint64(c-'0')
	}
	return v, nil
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
