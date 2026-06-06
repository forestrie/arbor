package univocity

import (
	"bytes"
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

// AuthorityResult is the resolved authority for a logId: the authoritative
// ES256 root key plus the forest root and chain binding.
type AuthorityResult struct {
	LogID     logid.UUID
	RootLogID logid.UUID
	KeyX      [32]byte
	KeyY      [32]byte
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

// bootstrapKeyFromStore loads the genesis key from the owned store when the
// on-chain anchor is unavailable (unanchored dev/e2e mode).
func (a API) bootstrapKeyFromStore(ctx context.Context, forest ForestEntry) ([]byte, error) {
	if a.Store == nil {
		return nil, ErrStoreNotConfigured
	}
	body, err := a.Store.GetGenesis(ctx, forest.R)
	if err != nil {
		return nil, err
	}
	doc, err := parseGenesisDoc(body)
	if err != nil {
		return nil, err
	}
	return doc.GenesisKeyBytes(), nil
}

// bootstrapKey returns the 64-byte bootstrap key (x||y) for a forest, cached per
// (chainId, contract). Prefer on-chain bootstrapConfig(); when
// AllowUnanchoredGenesis is set, fall back to the stored genesis document.
func (a API) bootstrapKey(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
) ([]byte, error) {
	cacheKey := fmt.Sprintf("%d|%s", forest.ChainID, forest.Contract.Hex())
	if a.Bootstrap != nil {
		if k, ok := a.Bootstrap.get(cacheKey); ok {
			return k, nil
		}
	}
	_, key, err := reader.BootstrapConfig(ctx)
	if err != nil || len(key) != 64 {
		if a.AllowUnanchoredGenesis {
			storeKey, serr := a.bootstrapKeyFromStore(ctx, forest)
			if serr == nil && len(storeKey) == 64 {
				if a.Bootstrap != nil {
					a.Bootstrap.put(cacheKey, storeKey)
				}
				return storeKey, nil
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBootstrapUnavailable, err)
		}
		return nil, fmt.Errorf("bootstrap key must be 64 bytes, got %d", len(key))
	}
	if a.Bootstrap != nil {
		a.Bootstrap.put(cacheKey, key)
	}
	return key, nil
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
	ox, oy, err := a.ownerKeyXY(ctx, forest, reader, g.OwnerLogID, depth)
	if err != nil {
		return err
	}
	if err := verifyCoseSign1ES256(ts.cose, ox, oy); err != nil {
		return fmt.Errorf("grant envelope not signed by owner root key: %w", err)
	}
	if g.LogID == forest.R {
		if g.OwnerLogID != forest.R {
			return errors.New("root grant must be self-owned (owner == R)")
		}
		key, err := a.bootstrapKey(ctx, forest, reader)
		if err != nil {
			return err
		}
		if !bytes.Equal(g.GrantData, key) {
			return errors.New("root grantData does not match on-chain bootstrap key")
		}
	}
	return nil
}

// ownerKeyXY resolves an owner/authority log's ES256 root key (x,y), preferring
// the on-chain logRootKey and falling back to the off-chain grant chain. The
// recursion anchors at the forest bootstrap key (owner == R).
func (a API) ownerKeyXY(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
	owner logid.UUID,
	depth int,
) (x, y [32]byte, err error) {
	if depth > maxGrantChainDepth {
		return [32]byte{}, [32]byte{}, errors.New("grant chain exceeds max depth")
	}
	if owner == forest.R {
		key, err := a.bootstrapKey(ctx, forest, reader)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		bx, by, ok := grantDataToXY(key)
		if !ok {
			return [32]byte{}, [32]byte{}, errors.New("bootstrap key is not 64 bytes")
		}
		return bx, by, nil
	}
	initialized, err := a.isLogInitialized(ctx, reader, owner)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("isLogInitialized(owner): %w", err)
	}
	if initialized {
		kx, ky, err := reader.LogRootKey(ctx, owner)
		if err != nil {
			return [32]byte{}, [32]byte{}, fmt.Errorf("logRootKey(owner): %w", err)
		}
		return kx, ky, nil
	}
	if a.Store == nil {
		return [32]byte{}, [32]byte{}, ErrStoreNotConfigured
	}
	body, err := a.Store.GetGrant(ctx, forest.R, owner)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("owner grant unavailable: %w", err)
	}
	ts, err := decodeTransparentStatement(body)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("decode owner grant: %w", err)
	}
	if ts.Grant.LogID != owner {
		return [32]byte{}, [32]byte{}, errors.New("owner grant subject mismatch")
	}
	if err := a.verifyGrantChainDepth(ctx, forest, reader, ts, depth+1); err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	kx, ky, ok := grantDataToXY(ts.Grant.GrantData)
	if !ok {
		return [32]byte{}, [32]byte{}, errors.New("owner grantData is not a 64-byte ES256 key")
	}
	return kx, ky, nil
}

// logRootKeyXY resolves the ES256 root key that signs a log's delegation /
// checkpoint: on-chain logRootKey when initialized, else the (chain-valid)
// stored grantData. For the forest root it is the on-chain bootstrap key.
func (a API) logRootKeyXY(
	ctx context.Context,
	forest ForestEntry,
	reader ChainReader,
	logID logid.UUID,
) (x, y [32]byte, source string, err error) {
	if logID == forest.R {
		key, err := a.bootstrapKey(ctx, forest, reader)
		if err != nil {
			return [32]byte{}, [32]byte{}, "", err
		}
		bx, by, ok := grantDataToXY(key)
		if !ok {
			return [32]byte{}, [32]byte{}, "", errors.New("bootstrap key is not 64 bytes")
		}
		return bx, by, "chain", nil
	}
	initialized, err := a.isLogInitialized(ctx, reader, logID)
	if err != nil {
		return [32]byte{}, [32]byte{}, "", fmt.Errorf("isLogInitialized: %w", err)
	}
	if initialized {
		kx, ky, err := reader.LogRootKey(ctx, logID)
		if err != nil {
			return [32]byte{}, [32]byte{}, "", fmt.Errorf("logRootKey: %w", err)
		}
		return kx, ky, "chain", nil
	}
	if a.Store == nil {
		return [32]byte{}, [32]byte{}, "", ErrStoreNotConfigured
	}
	body, err := a.Store.GetGrant(ctx, forest.R, logID)
	if err != nil {
		return [32]byte{}, [32]byte{}, "", fmt.Errorf("grant unavailable: %w", err)
	}
	ts, err := decodeTransparentStatement(body)
	if err != nil {
		return [32]byte{}, [32]byte{}, "", fmt.Errorf("decode grant: %w", err)
	}
	if ts.Grant.LogID != logID {
		return [32]byte{}, [32]byte{}, "", errors.New("grant subject mismatch")
	}
	if err := a.verifyGrantChain(ctx, forest, reader, ts); err != nil {
		return [32]byte{}, [32]byte{}, "", err
	}
	kx, ky, ok := grantDataToXY(ts.Grant.GrantData)
	if !ok {
		return [32]byte{}, [32]byte{}, "", errors.New("grantData is not a 64-byte ES256 key")
	}
	return kx, ky, "grant", nil
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
	kx, ky, source, err := a.logRootKeyXY(ctx, forest, reader, logID)
	if err != nil {
		return AuthorityResult{}, err
	}
	return AuthorityResult{
		LogID:     logID,
		RootLogID: forest.R,
		KeyX:      kx,
		KeyY:      ky,
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
