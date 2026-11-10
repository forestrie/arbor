package univocity

import (
	"context"
	"errors"
	"fmt"

	"github.com/forestrie/arbor/services/pkgs/logid"
)

const maxGrantChainDepth = 32

// ErrBootstrapUnavailable indicates the on-chain bootstrap anchor could not be
// read (chain not configured or contract call failed).
var ErrBootstrapUnavailable = errors.New("on-chain bootstrap anchor unavailable")

// bootstrapConfig returns the contract's bootstrap (alg,key) for a forest:
// the forest root's key, which comes only from the contract (devdocs
// ADR-0075 decision 7). It is immutable per (chainId, contract), so a valid
// answer is cached for good; a failed read is never cached.
func (a API) bootstrapConfig(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
) (int64, []byte, error) {
	cacheKey := fmt.Sprintf("%d|%s", forest.ChainID, forest.Contract.Hex())
	if a.Bootstrap != nil {
		if e, ok := a.Bootstrap.get(cacheKey); ok {
			return e.alg, e.key, nil
		}
	}
	alg, key, err := reader.BootstrapConfig(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrBootstrapUnavailable, err)
	}
	if !validBootstrapIdentity(alg, key) {
		return 0, nil, fmt.Errorf("bootstrap key invalid for alg %d (len %d)", alg, len(key))
	}
	if a.Bootstrap != nil {
		a.Bootstrap.put(cacheKey, alg, key)
	}
	return alg, key, nil
}

func validBootstrapIdentity(alg int64, key []byte) bool {
	switch alg {
	case coseAlgES256:
		return len(key) == 64
	case coseAlgKS256:
		return len(key) == 20
	default:
		return false
	}
}

func (a API) isLogInitialized(
	ctx context.Context,
	reader ChainReader,
	logID logid.UUID,
) (bool, error) {
	return reader.IsLogInitialized(ctx, logID)
}

// verifyGrantChain verifies a creation grant's envelope is signed by its owner's
// root key and that the chain anchors at the forest bootstrap key. Returns nil
// when the grant is a chain-valid creation grant.
func (a API) verifyGrantChain(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
	ts TransparentStatement,
) error {
	return a.verifyGrantChainDepth(ctx, forest, reader, ts, 0)
}

func (a API) verifyGrantChainDepth(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
	ts TransparentStatement,
	depth int,
) error {
	g := ts.Grant
	ownerAlg, ownerKey, err := a.ownerRootKey(ctx, forest, reader, g.OwnerLogID, depth)
	if err != nil {
		return err
	}
	if err := verifyGrantEnvelope(ctx, ts.cose, ownerAlg, ownerKey, reader); err != nil {
		return fmt.Errorf("grant envelope not signed by owner root key: %w", err)
	}
	if g.LogID == forest.R {
		if g.OwnerLogID != forest.R {
			return errors.New("root grant must be self-owned (owner == R)")
		}
		bootAlg, bootKey, err := a.bootstrapConfig(ctx, forest, reader)
		if err != nil {
			return err
		}
		grantAlg, grantKey, ok := grantDataIdentity(g.GrantData)
		if !ok || !bootstrapKeysEqual(grantAlg, grantKey, bootAlg, bootKey) {
			return errors.New("root grantData does not match on-chain bootstrap key")
		}
	}
	return nil
}

// ownerRootKey resolves an owner/authority log's root identity (alg,key),
// preferring on-chain logConfig.rootKey and falling back to the off-chain grant
// chain. The recursion anchors at the forest bootstrap key (owner == R).
func (a API) ownerRootKey(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
	owner logid.UUID,
	depth int,
) (alg int64, key []byte, err error) {
	if depth > maxGrantChainDepth {
		return 0, nil, errors.New("grant chain exceeds max depth")
	}
	if owner == forest.R {
		return a.bootstrapConfig(ctx, forest, reader)
	}
	initialized, err := a.isLogInitialized(ctx, reader, owner)
	if err != nil {
		return 0, nil, fmt.Errorf("isLogInitialized(owner): %w", err)
	}
	if initialized {
		cfg, err := reader.LogConfig(ctx, owner)
		if err != nil {
			return 0, nil, fmt.Errorf("logConfig(owner): %w", err)
		}
		alg, key, ok := grantDataIdentity(cfg.RootKey)
		if !ok {
			return 0, nil, fmt.Errorf("on-chain rootKey has invalid length %d", len(cfg.RootKey))
		}
		return alg, key, nil
	}
	c, err := a.claimedGrant(ctx, forest.R, owner)
	if err != nil {
		return 0, nil, fmt.Errorf("owner grant unavailable: %w", err)
	}
	ts, err := decodeTransparentStatement(c.statement)
	if err != nil {
		return 0, nil, fmt.Errorf("decode owner grant: %w", err)
	}
	if ts.Grant.LogID != owner {
		return 0, nil, errors.New("owner grant subject mismatch")
	}
	if err := a.verifyGrantChainDepth(ctx, forest, reader, ts, depth+1); err != nil {
		return 0, nil, err
	}
	alg, key, ok := grantDataIdentity(ts.Grant.GrantData)
	if !ok {
		return 0, nil, errors.New("owner grantData is not a valid opaque root key")
	}
	return alg, key, nil
}

// loadForest reads and parses a forest genesis document from the owned store.
func (a API) loadForest(ctx context.Context, r logid.UUID) (ForestEntry, error) {
	if a.Store == nil {
		return ForestEntry{}, ErrStoreNotConfigured
	}
	body, err := a.Store.GetGenesis(ctx, r)
	if err != nil {
		return ForestEntry{}, err
	}
	doc, err := parseGenesisDoc(body)
	if err != nil {
		return ForestEntry{}, err
	}
	if doc.Forest.R != r {
		return ForestEntry{}, errors.New("genesis bootstrap-logid does not match object key")
	}
	a.Registrations.watch(doc.Forest)
	return doc.Forest, nil
}
