package univocity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
)

const maxGrantChainDepth = 32

// ErrBootstrapUnavailable indicates the on-chain bootstrap anchor could not be
// read (chain not configured or contract call failed).
var ErrBootstrapUnavailable = errors.New("on-chain bootstrap anchor unavailable")

// AuthorityResult is the resolved authority for a logId: the authoritative root
// identity (alg + opaque key) plus the forest root and chain binding.
type AuthorityResult struct {
	LogID     logid.UUID
	RootLogID logid.UUID
	Alg       int64
	Key       []byte // opaque 64 (ES256) or 20 (KS256)
	ChainID   uint64
	Contract  common.Address
	Source    string // "chain" | "grant"
}

// isContractReadUnavailable reports RPC/ABI failures typical when no contract
// is deployed at the genesis-bound address (empty eth_call return data).
func isContractReadUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrBootstrapUnavailable) {
		return true
	}
	return strings.Contains(err.Error(), "attempting to unmarshal an empty string")
}

// bootstrapConfigFromStore loads genesis (alg,key) from the owned store when the
// on-chain anchor is unavailable (unanchored dev/e2e mode).
func (a API) bootstrapConfigFromStore(ctx context.Context, forest ForestEntry) (int64, []byte, error) {
	if a.Store == nil {
		return 0, nil, ErrStoreNotConfigured
	}
	body, err := a.Store.GetGenesis(ctx, forest.R)
	if err != nil {
		return 0, nil, err
	}
	doc, err := parseGenesisDoc(body)
	if err != nil {
		return 0, nil, err
	}
	return doc.Alg, doc.GenesisKeyBytes(), nil
}

// bootstrapConfig returns the on-chain bootstrap (alg,key) for a forest, cached
// per (chainId, contract). Prefer bootstrapConfig(); when AllowUnanchoredGenesis
// is set, fall back to the stored genesis document.
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
	if err != nil || !validBootstrapIdentity(alg, key) {
		if a.AllowUnanchoredGenesis {
			storeAlg, storeKey, serr := a.bootstrapConfigFromStore(ctx, forest)
			if serr == nil && validBootstrapIdentity(storeAlg, storeKey) {
				if a.Bootstrap != nil {
					a.Bootstrap.put(cacheKey, storeAlg, storeKey)
				}
				return storeAlg, storeKey, nil
			}
		}
		if err != nil {
			return 0, nil, fmt.Errorf("%w: %v", ErrBootstrapUnavailable, err)
		}
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
	ok, err := reader.IsLogInitialized(ctx, logID)
	if err != nil && a.AllowUnanchoredGenesis && isContractReadUnavailable(err) {
		return false, nil
	}
	return ok, err
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
	if a.Store == nil {
		return 0, nil, ErrStoreNotConfigured
	}
	body, err := a.Store.GetGrant(ctx, forest.R, owner)
	if err != nil {
		return 0, nil, fmt.Errorf("owner grant unavailable: %w", err)
	}
	ts, err := decodeTransparentStatement(body)
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

// logRootKey resolves the opaque root identity that signs a log's delegation /
// checkpoint: on-chain logConfig.rootKey when initialized, else the (chain-valid)
// stored grantData. For the forest root it is the on-chain bootstrap key.
func (a API) logRootKey(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
	logID logid.UUID,
) (alg int64, key []byte, source string, err error) {
	if logID == forest.R {
		alg, key, err := a.bootstrapConfig(ctx, forest, reader)
		return alg, key, "chain", err
	}
	initialized, err := a.isLogInitialized(ctx, reader, logID)
	if err != nil {
		return 0, nil, "", fmt.Errorf("isLogInitialized: %w", err)
	}
	if initialized {
		cfg, err := reader.LogConfig(ctx, logID)
		if err != nil {
			return 0, nil, "", fmt.Errorf("logConfig: %w", err)
		}
		alg, key, ok := grantDataIdentity(cfg.RootKey)
		if !ok {
			return 0, nil, "", fmt.Errorf("on-chain rootKey has invalid length %d", len(cfg.RootKey))
		}
		return alg, key, "chain", nil
	}
	if a.Store == nil {
		return 0, nil, "", ErrStoreNotConfigured
	}
	body, err := a.Store.GetGrant(ctx, forest.R, logID)
	if err != nil {
		return 0, nil, "", fmt.Errorf("grant unavailable: %w", err)
	}
	ts, err := decodeTransparentStatement(body)
	if err != nil {
		return 0, nil, "", fmt.Errorf("decode grant: %w", err)
	}
	if ts.Grant.LogID != logID {
		return 0, nil, "", errors.New("grant subject mismatch")
	}
	if err := a.verifyGrantChain(ctx, forest, reader, ts); err != nil {
		return 0, nil, "", err
	}
	alg, key, ok := grantDataIdentity(ts.Grant.GrantData)
	if !ok {
		return 0, nil, "", errors.New("grantData is not a valid opaque root key")
	}
	return alg, key, "grant", nil
}

// resolveAuthority resolves the authoritative root key + chain binding for a
// logId via the hybrid path (index -> forest, then chain logRootKey or the
// chain-valid stored grant chain). It performs no certificate verification: the
// sealer verifies the (untrusted) delegation certificate locally against the
// returned key.
func (a API) resolveAuthority(
	ctx context.Context,
	logID logid.UUID,
) (AuthorityResult, error) {
	forest, reader, err := a.resolveForestForLog(ctx, logID)
	if err != nil {
		return AuthorityResult{}, err
	}
	alg, key, source, err := a.logRootKey(ctx, forest, reader, logID)
	if err != nil {
		return AuthorityResult{}, err
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return AuthorityResult{
		LogID:     logID,
		RootLogID: forest.R,
		Alg:       alg,
		Key:       keyCopy,
		ChainID:   forest.ChainID,
		Contract:  forest.Contract,
		Source:    source,
	}, nil
}

// resolveForestForLog finds the forest for a subject log: index->R (owned store)
// first, then the genesis-identity + on-chain-probe resolver as a fallback.
func (a API) resolveForestForLog(
	ctx context.Context,
	logID logid.UUID,
) (ForestEntry, ChainReader, error) {
	if a.Store != nil {
		if r, found, err := a.Store.IndexGet(ctx, logID); err == nil && found {
			forest, err := a.loadForest(ctx, r)
			if err != nil {
				return ForestEntry{}, nil, fmt.Errorf("load forest for index: %w", err)
			}
			reader, err := a.Pool.Reader(forest.ChainID, forest.Contract)
			if err != nil {
				return ForestEntry{}, nil, err
			}
			return forest, reader, nil
		}
	}
	if a.Resolver != nil {
		forest, err := a.Resolver.Resolve(ctx, logID)
		if err != nil {
			return ForestEntry{}, nil, err
		}
		reader, err := a.Pool.Reader(forest.ChainID, forest.Contract)
		if err != nil {
			return ForestEntry{}, nil, err
		}
		return forest, reader, nil
	}
	return ForestEntry{}, nil, ErrLogNotResolved
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
	return doc.Forest, nil
}
