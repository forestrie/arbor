package univocity

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
)

// ForestRegistry loads v1 genesis documents from the grants R2 bucket.
type ForestRegistry struct {
	logger  *slog.Logger
	s3      *s3.Client
	rpcURLs map[uint64]bool
	scanMin time.Duration

	mu       sync.RWMutex
	forests  []ForestEntry
	lastScan time.Time
	scanMu   sync.Mutex
}

// NewForestRegistry constructs a registry; call Scan before serving traffic.
func NewForestRegistry(
	logger *slog.Logger,
	client *s3.Client,
	rpcURLs map[uint64]string,
	scanMinInterval time.Duration,
) *ForestRegistry {
	allowed := make(map[uint64]bool, len(rpcURLs))
	for id := range rpcURLs {
		allowed[id] = true
	}
	return &ForestRegistry{
		logger:  logger,
		s3:      client,
		rpcURLs: allowed,
		scanMin: scanMinInterval,
	}
}

// Forests returns a snapshot of registered forests.
func (r *ForestRegistry) Forests() []ForestEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ForestEntry, len(r.forests))
	copy(out, r.forests)
	return out
}

// Scan lists forests/forest/{uuid}/genesis.cbor and replaces the in-memory forest list.
func (r *ForestRegistry) Scan(ctx context.Context) error {
	r.scanMu.Lock()
	defer r.scanMu.Unlock()
	return r.scanLocked(ctx)
}

func (r *ForestRegistry) scanLocked(ctx context.Context) error {
	var entries []ForestEntry
	continuation := ""
	for {
		page, err := r.s3.ListObjects(ctx, forestGenesisPrefix, continuation, 1000)
		if err != nil {
			return fmt.Errorf("list genesis objects: %w", err)
		}
		for _, obj := range page.Objects {
			uuidStr, ok := parseForestGenesisKey(obj.Key)
			if !ok {
				continue
			}
			entry, err := r.loadGenesis(ctx, uuidStr)
			if err != nil {
				r.logger.Warn("skip genesis object", "key", obj.Key, "error", err)
				continue
			}
			if !r.rpcURLs[entry.ChainID] {
				r.logger.Warn(
					"skip genesis forest: chainId not in UNIVOCITY_RPC_URLS",
					"chainId", entry.ChainID,
					"R", entry.R.String(),
				)
				continue
			}
			entries = append(entries, entry)
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		continuation = page.NextContinuationToken
	}

	r.mu.Lock()
	r.forests = entries
	r.lastScan = time.Now()
	r.mu.Unlock()
	r.logger.Info("forest registry scan complete", "forests", len(entries))
	return nil
}

func (r *ForestRegistry) loadGenesis(ctx context.Context, uuidStr string) (ForestEntry, error) {
	key := forestGenesisObjectKey(uuidStr)
	res, err := r.s3.GetObject(ctx, key, s3.GetOptions{})
	if err != nil {
		return ForestEntry{}, err
	}
	const maxGenesis = 64 * 1024
	body := res.Data
	if len(body) > maxGenesis {
		body = body[:maxGenesis]
	}
	entry, err := parseGenesisV1(body)
	if err != nil {
		return ForestEntry{}, err
	}
	pathID, err := logid.ParseUUIDString(uuidStr)
	if err != nil {
		return ForestEntry{}, fmt.Errorf("invalid object key uuid: %w", err)
	}
	if entry.R != pathID {
		return ForestEntry{}, fmt.Errorf("bootstrap-logid does not match object key")
	}
	return entry, nil
}

// TryRefreshScan runs Scan if the circuit breaker allows (coalesced under scanMu).
func (r *ForestRegistry) TryRefreshScan(ctx context.Context) (bool, error) {
	r.scanMu.Lock()
	defer r.scanMu.Unlock()
	r.mu.RLock()
	elapsed := time.Since(r.lastScan)
	r.mu.RUnlock()
	if elapsed < r.scanMin {
		return false, nil
	}
	if err := r.scanLocked(ctx); err != nil {
		return false, err
	}
	return true, nil
}
