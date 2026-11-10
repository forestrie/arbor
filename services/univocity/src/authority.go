package univocity

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/arbor/services/pkgs/publishproof"
)

// A log's authority is used only once it is anchored on chain (protocol
// ADR-0070). Univocity answers, for each claimed log, how far its claim has
// got (devdocs ADR-0075 decision 9):
//
//	reserved   prepared, with a lapse time; the claim verifies to the
//	           bootstrap key through the stored grant chain
//	committed  registered for sequencing; its leaf is not yet found
//	sequenced  the create grant's leaf is in the owner's log
//	anchored   the forest root's contract is deployed, or the log has a
//	           published checkpoint matching its claim, or a published
//	           checkpoint of the owner covers the create grant's leaf
//	conflicted the chain recorded a different owner or key at the log's
//	           first checkpoint; final, and replaces any other state
//
// Only anchored grants authority, and only when no ancestor is blocked.
const (
	stateSequenced  = "sequenced"
	stateAnchored   = "anchored"
	stateConflicted = "conflicted"
)

// Authority is univocity's answer for one log.
type Authority struct {
	LogID     logid.UUID
	RootLogID logid.UUID
	// OwnerLogID is the owner the claim names, or for a log on chain the
	// owner the chain recorded.
	OwnerLogID logid.UUID
	ChainID    uint64
	Contract   common.Address
	State      string
	// Alg and Key are the log's root key: the chain's once the log is on
	// chain, else the claim's grantData. A root whose contract cannot be
	// read has none.
	Alg    int64
	Key    []byte
	Source string // "chain" or "grant"
	// ExpiresAt is a reservation's lapse time.
	ExpiresAt time.Time
	// BlockedBy is the ancestor nearest the root that is not anchored, or
	// is conflicted. Anchoring proceeds from the root down, so it is the log
	// that must anchor next. Zero when every ancestor is anchored.
	BlockedBy logid.UUID
	// blockedByConflict is true when BlockedBy is conflicted, which no
	// amount of waiting resolves.
	blockedByConflict bool
	// Final is true once the answer cannot change: the forest root once its
	// contract is deployed; any other log once its first checkpoint has been
	// compared with its claim and its owner's answer is final too, since an
	// owner anchored by its leaf can still turn out conflicted.
	Final bool
}

// usable reports whether the log's authority may be relied on.
func (x Authority) usable() bool {
	return x.State == stateAnchored && x.BlockedBy.IsZero()
}

// conflictsDetected counts first registrations found to differ from their
// claim, for /metrics.
var conflictsDetected atomic.Uint64

// ConflictsDetected returns the number of conflicting first registrations
// detected since start.
func ConflictsDetected() uint64 { return conflictsDetected.Load() }

// resolveAuthority answers a log's authority: from the cache when the answer
// is final (or anchored and recently checked), else computed.
func (a API) resolveAuthority(ctx context.Context, logID, hint logid.UUID) (Authority, error) {
	if x, ok := a.Authorities.get(logID, a.now()); ok {
		return x, nil
	}
	forest, reader, err := a.resolveForestForLog(ctx, logID, hint)
	if err != nil {
		return Authority{}, err
	}
	return a.authorityIn(ctx, forest, reader, logID, 0)
}

func (a API) authorityIn(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
	logID logid.UUID,
	depth int,
) (Authority, error) {
	if depth > maxGrantChainDepth {
		return Authority{}, errors.New("grant chain exceeds max depth")
	}
	if x, ok := a.Authorities.get(logID, a.now()); ok {
		return x, nil
	}
	base := Authority{
		LogID:     logID,
		RootLogID: forest.R,
		ChainID:   forest.ChainID,
		Contract:  forest.Contract,
	}
	var (
		x   Authority
		err error
	)
	if logID == forest.R {
		x, err = a.rootAuthority(ctx, forest, reader, base)
	} else {
		x, err = a.childAuthority(ctx, forest, reader, base, depth)
	}
	if err != nil {
		return Authority{}, err
	}
	a.Authorities.put(x, a.now())
	return x, nil
}

// rootAuthority: the root's key is the contract's bootstrap key, so the root
// is anchored, finally, once the contract can be read, and pending while no
// contract is deployed at the genesis address. A failed read of a deployed
// contract is an outage, reported as an error.
func (a API) rootAuthority(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
	x Authority,
) (Authority, error) {
	x.OwnerLogID = forest.R
	alg, key, err := a.bootstrapConfig(ctx, forest, reader)
	if errors.Is(err, ErrBootstrapUnavailable) {
		deployed, cerr := reader.HasCode(ctx, forest.Contract)
		if cerr != nil {
			return Authority{}, fmt.Errorf("%w; contract code: %v", err, cerr)
		}
		if deployed {
			return Authority{}, err
		}
		x.State = stateCommitted
		return x, nil
	}
	if err != nil {
		return Authority{}, err
	}
	x.State, x.Final = stateAnchored, true
	x.Alg, x.Key, x.Source = alg, append([]byte(nil), key...), "chain"
	return x, nil
}

func (a API) childAuthority(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
	x Authority,
	depth int,
) (Authority, error) {
	c, err := a.claimedGrant(ctx, forest.R, x.LogID)
	if errors.Is(err, errNoClaim) {
		return Authority{}, notResolved("log %s has no claim in forest %s", x.LogID, forest.R)
	}
	if err != nil {
		return Authority{}, err
	}
	ts, err := decodeTransparentStatement(c.statement)
	if err != nil {
		return Authority{}, fmt.Errorf("decode claimed grant: %w", err)
	}
	g := ts.Grant
	if g.LogID != x.LogID {
		return Authority{}, errors.New("claimed grant subject mismatch")
	}
	x.OwnerLogID = g.OwnerLogID

	initialized, err := reader.IsLogInitialized(ctx, x.LogID)
	if err != nil {
		return Authority{}, fmt.Errorf("isLogInitialized: %w", err)
	}
	if initialized {
		x, err = a.compareFirstCheckpoint(ctx, reader, x, g)
		if err != nil || x.State == stateConflicted {
			return x, err
		}
	}
	var ownerSettled bool
	x.BlockedBy, x.blockedByConflict, ownerSettled, err = a.blockedBy(ctx, forest, reader, x.OwnerLogID, depth)
	if err != nil {
		return Authority{}, err
	}
	if initialized {
		x.Final = x.Final && ownerSettled
		return x, nil
	}

	alg, key, ok := grantDataIdentity(g.GrantData)
	if !ok {
		return Authority{}, errors.New("grantData is not a valid opaque root key")
	}
	x.Alg, x.Key, x.Source = alg, append([]byte(nil), key...), "grant"
	if c.state == stateReserved {
		x.State, x.ExpiresAt = stateReserved, c.expiresAt
	} else {
		x.State = stateCommitted
	}
	if x.blockedByConflict {
		// The claim cannot verify through an ancestor the chain recorded
		// differently, and confers nothing while that ancestor blocks it.
		return x, nil
	}
	// Not on chain: the claim must verify to the bootstrap key.
	if err := a.verifyGrantChain(ctx, forest, reader, ts); err != nil {
		return Authority{}, err
	}
	if c.state != stateReserved {
		x.State, err = a.leafState(ctx, reader, x.LogID, g.OwnerLogID, c.statement)
		if err != nil {
			return Authority{}, err
		}
	}
	return x, nil
}

// compareFirstCheckpoint compares the owner and key the chain recorded at a
// log's first checkpoint with the claim (devdocs ADR-0075 decision 8,
// protocol ADR-0070 decision 6). Either way the answer is final.
func (a API) compareFirstCheckpoint(
	ctx context.Context,
	reader ChainReader,
	x Authority,
	g Grant,
) (Authority, error) {
	cfg, err := reader.LogConfig(ctx, x.LogID)
	if err != nil {
		return Authority{}, fmt.Errorf("logConfig: %w", err)
	}
	chainAlg, chainKey, ok := grantDataIdentity(cfg.RootKey)
	if !ok {
		return Authority{}, fmt.Errorf("on-chain rootKey has invalid length %d", len(cfg.RootKey))
	}
	claimAlg, claimKey, claimOK := grantDataIdentity(g.GrantData)
	x.Final = true
	x.OwnerLogID = cfg.AuthLogId
	x.Alg, x.Key, x.Source = chainAlg, append([]byte(nil), chainKey...), "chain"
	if cfg.AuthLogId == g.OwnerLogID && claimOK &&
		bootstrapKeysEqual(claimAlg, claimKey, chainAlg, chainKey) {
		x.State = stateAnchored
		return x, nil
	}
	x.State = stateConflicted
	conflictsDetected.Add(1)
	a.Logger.Error("log registered on chain differs from its claim",
		"alarm", "authority-conflict",
		"logId", x.LogID.String(),
		"R", x.RootLogID.String(),
		"claimOwner", g.OwnerLogID.String(),
		"chainOwner", cfg.AuthLogId.String(),
		"keyMatches", claimOK && bootstrapKeysEqual(claimAlg, claimKey, chainAlg, chainKey),
	)
	return x, nil
}

// leafState finds a committed create grant's leaf in its owner's log and
// whether a published checkpoint of the owner covers it, proved against the
// owner's on-chain accumulator.
func (a API) leafState(
	ctx context.Context,
	reader ChainReader,
	logID, owner logid.UUID,
	statement []byte,
) (string, error) {
	if a.Authorities.leafAnchored(logID) {
		return stateAnchored, nil
	}
	if a.Massifs == nil || a.Leaves == nil {
		return "", errMassifsNotConfigured
	}
	contentHash, err := publishproof.StoredGrantContentHash(statement)
	if err != nil {
		return "", fmt.Errorf("claimed grant content hash: %w", err)
	}
	ownerLog, err := a.Massifs.Massif(ctx, owner)
	if err != nil {
		return "", fmt.Errorf("owner log reader: %w", err)
	}
	gl, found, err := a.Leaves.Find(ctx, owner, ownerLog, contentHash)
	if err != nil {
		return "", fmt.Errorf("owner leaf scan: %w", err)
	}
	if !found {
		return stateCommitted, nil
	}
	state, err := reader.LogState(ctx, owner)
	if err != nil {
		return "", fmt.Errorf("owner logState: %w", err)
	}
	// A fresh reader, opened after the on-chain state is read, holds at
	// least the published size: the scan's reader caches the head massif
	// as it was, and the owner may have grown and published since.
	ownerLog, err = a.Massifs.Massif(ctx, owner)
	if err != nil {
		return "", fmt.Errorf("owner log reader: %w", err)
	}
	covered, err := publishproof.VerifyGrantLeafAnchored(ctx, ownerLog, a.Massifs.MassifHeight(), state, gl)
	if err != nil {
		a.Logger.Error("owner log disagrees with its on-chain accumulator",
			"logId", logID.String(), "owner", owner.String(), "error", err)
		return "", fmt.Errorf("prove create grant leaf: %w", err)
	}
	if !covered {
		return stateSequenced, nil
	}
	a.Authorities.markLeafAnchored(logID)
	return stateAnchored, nil
}

// blockedBy names the ancestor nearest the root that is not anchored, or is
// conflicted, starting from owner; whether that ancestor is conflicted; and
// whether the owner's answer is settled, so cannot change what it implies
// for its children.
func (a API) blockedBy(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
	owner logid.UUID,
	depth int,
) (blocker logid.UUID, conflict, settled bool, err error) {
	o, err := a.authorityIn(ctx, forest, reader, owner, depth+1)
	if err != nil {
		return logid.Zero, false, false, fmt.Errorf("owner %s authority: %w", owner, err)
	}
	settled = o.Final || o.blockedByConflict
	if !o.BlockedBy.IsZero() {
		return o.BlockedBy, o.blockedByConflict, settled, nil
	}
	if o.State != stateAnchored {
		return owner, o.State == stateConflicted, settled, nil
	}
	return logid.Zero, false, settled, nil
}
