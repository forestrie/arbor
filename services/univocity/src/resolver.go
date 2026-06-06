package univocity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/forestrie/arbor/services/pkgs/logid"
)

var (
	ErrLogNotResolved  = errors.New("log id not resolved to a forest")
	ErrAmbiguousForest = errors.New("log id matches more than one forest")
)

// ForestResolver resolves logId -> forest using genesis registry and on-chain probes.
type ForestResolver struct {
	logger   *slog.Logger
	registry *ForestRegistry
	pool     ChainResolver
	cache    *forestLRUCache
}

// NewForestResolver wires registry, RPC pool, and bounded caches.
func NewForestResolver(
	logger *slog.Logger,
	registry *ForestRegistry,
	pool ChainResolver,
	cacheSize int,
	negTTL time.Duration,
) *ForestResolver {
	return &ForestResolver{
		logger:   logger,
		registry: registry,
		pool:     pool,
		cache:    newForestLRUCache(cacheSize, negTTL),
	}
}

// OnRegistryScan clears positive cache after registry refresh.
func (f *ForestResolver) OnRegistryScan() {
	f.cache.Clear()
}

// Resolve finds the forest for logID.
func (f *ForestResolver) Resolve(ctx context.Context, logID logid.UUID) (ForestEntry, error) {
	if e, ok, neg := f.cache.Get(logID); neg {
		return ForestEntry{}, ErrLogNotResolved
	} else if ok {
		return e, nil
	}

	forests := f.registry.Forests()
	if e, ok := matchGenesisIdentity(logID, forests); ok {
		f.cache.PutPositive(logID, e)
		return e, nil
	}
	if e, found, err := f.probeForests(ctx, logID, forests); err != nil {
		return ForestEntry{}, err
	} else if found {
		f.cache.PutPositive(logID, e)
		return e, nil
	}

	refreshed, err := f.registry.TryRefreshScan(ctx)
	if err != nil {
		f.logger.Error("genesis registry refresh failed", "error", err)
	}
	if refreshed {
		f.OnRegistryScan()
		forests = f.registry.Forests()
		if e, ok := matchGenesisIdentity(logID, forests); ok {
			f.cache.PutPositive(logID, e)
			return e, nil
		}
		if e, found, err := f.probeForests(ctx, logID, forests); err != nil {
			return ForestEntry{}, err
		} else if found {
			f.cache.PutPositive(logID, e)
			return e, nil
		}
	}

	f.cache.PutNegative(logID)
	return ForestEntry{}, ErrLogNotResolved
}

func matchGenesisIdentity(logID logid.UUID, forests []ForestEntry) (ForestEntry, bool) {
	for _, e := range forests {
		if e.R == logID {
			return e, true
		}
	}
	return ForestEntry{}, false
}

func (f *ForestResolver) probeForests(
	ctx context.Context,
	logID logid.UUID,
	forests []ForestEntry,
) (ForestEntry, bool, error) {
	var matches []ForestEntry
	for _, e := range forests {
		reader, err := f.pool.Reader(e.ChainID, e.Contract)
		if err != nil {
			if errors.Is(err, ErrChainNotConfigured) {
				continue
			}
			return ForestEntry{}, false, fmt.Errorf("rpc reader: %w", err)
		}
		ok, err := reader.IsLogInitialized(ctx, logID)
		if err != nil {
			return ForestEntry{}, false, fmt.Errorf("isLogInitialized: %w", err)
		}
		if ok {
			matches = append(matches, e)
		}
	}
	switch len(matches) {
	case 0:
		return ForestEntry{}, false, nil
	case 1:
		return matches[0], true, nil
	default:
		f.logger.Error(
			"ambiguous logId across forests",
			"logId", logID.String(),
			"matchCount", len(matches),
		)
		return ForestEntry{}, false, ErrAmbiguousForest
	}
}
