// Package committer provides batch processing of entries into the merklelog.
//
// This package implements the ranger service's core functionality: committing
// entries from the DO ingress queue into the S3-backed merklelog storage.
//
// See: arbor/docs/arc-cloudflare-do-ingress.md
package committer

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/ranger"
	"github.com/forestrie/arbor/services/ranger/consumer/ingress"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/massifs/snowflakeid"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
)

// Committer commits batches of entries into the merklelog.
type Committer struct {
	factory         *merklelog.Factory
	idState         *snowflakeid.IDState
	logger          *slog.Logger
	massifHeight    uint8
	commitmentEpoch uint32
}

// NewCommitter creates a new Committer instance backed by an S3-compatible
// storage backend (Cloudflare R2 or MinIO for tests).
func NewCommitter(cfg ranger.Config, httpClient *ranger.HTTPClient, logger *slog.Logger) (*Committer, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("http client is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	massifHeight := cfg.MassifHeight
	if massifHeight == 0 {
		massifHeight = 14
	}

	factory, err := merklelog.NewS3FactoryWithCredentials(
		cfg.R2URL,
		"", // no bearer token; use SigV4
		cfg.AWSAccessKeyID,
		cfg.AWSSecretAccessKey,
		cfg.AWSRegion,
		massifHeight,
		httpClient,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage factory: %w", err)
	}

	idState, err := snowflakeid.NewIDState(snowflakeid.Config{
		CommitmentEpoch: uint8(cfg.CommitmentEpoch),
		WorkerCIDR:      cfg.WorkerCIDR,
		PodIP:           cfg.PodIP,
		AllowSpins:      snowflakeid.MaxSpins,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ID state: %w", err)
	}

	return &Committer{
		factory:         factory,
		idState:         idState,
		logger:          logger,
		massifHeight:    massifHeight,
		commitmentEpoch: cfg.CommitmentEpoch,
	}, nil
}

// CommitLogGroup commits entries from the DO ingress queue for a single log.
// Returns a CommitResult with the count of successfully committed entries
// and the sequencing metadata (firstLeafIndex, massifIndex) needed for ack.
//
// This method is called by the ingress consumer for each log group in parallel.
// See: arbor/docs/arc-cloudflare-do-ingress.md
//
// DUPLICATE COMMIT NOTE: If ack fails after this returns successfully,
// entries will redeliver and be re-committed. This is currently accepted.
// Future options to mitigate:
// - Bloom filter check before commit (arc-cloudflare-do-ingress.md 3.10.1)
// - Attempt-aware deduplication (3.10.2)
// - DO-allocated pre-sequence IDs (3.10.4)
func (c *Committer) CommitLogGroup(
	ctx context.Context,
	logId []byte,
	entries []ingress.Entry,
) (*ingress.CommitResult, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	logID := massifstorage.LogID(logId)
	logIDHex := fmt.Sprintf("%x", logId)

	store, err := c.factory.NewStore(logID)
	if err != nil {
		return nil, fmt.Errorf("create store for log %s: %w", logIDHex, err)
	}

	if err := store.SelectLog(ctx, logID); err != nil {
		return nil, fmt.Errorf("select log %s: %w", logIDHex, err)
	}

	mc, err := massifs.GetAppendContext(ctx, store, uint32(c.commitmentEpoch), c.massifHeight)
	if err != nil {
		return nil, fmt.Errorf("get append context: %w", err)
	}

	var (
		mmrSize        uint64
		lastCommit     int
		committedCount int
		firstLeafIndex uint64 = ^uint64(0) // sentinel: max uint64
		// R2 object keys of massifs written by this call, in write order.
		// Consumed by the seal-hint publisher after ack (ADR-0007 phase 1).
		massifKeys []string
	)

	// recordMassifKey captures the R2 object key for a massif we just
	// committed. Best-effort: a failure only costs the seal hint for that
	// massif (the R2 event notification backstop still triggers the seal).
	recordMassifKey := func(massifIndex uint32) {
		key, err := store.ObjectPath(massifIndex, massifstorage.ObjectMassifData)
		if err != nil {
			c.logger.Warn("massif object key for seal hint unavailable",
				"logId", logIDHex,
				"massifIndex", massifIndex,
				"error", err,
			)
			return
		}
		massifKeys = append(massifKeys, key)
	}

	for i, entry := range entries {
		if len(entry.ContentHash) != sha256.Size {
			c.logger.Warn("invalid content hash length",
				"logId", logIDHex,
				"index", i,
				"hashLen", len(entry.ContentHash),
			)
			continue
		}

		idTimestamp, err := mc.NextIDTimestamp(ctx, c.idState)
		if err != nil {
			c.logger.Warn("failed to generate id timestamp",
				"logId", logIDHex,
				"index", i,
				"error", err,
			)
			continue
		}

		idTimestampBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(idTimestampBytes, idTimestamp)

		hasher := sha256.New()
		hasher.Write(idTimestampBytes)
		hasher.Write(entry.ContentHash)
		leafHash := hasher.Sum(nil)

		if len(leafHash) != massifs.ValueBytes {
			c.logger.Warn("invalid leaf hash length",
				"logId", logIDHex,
				"index", i,
				"hashLen", len(leafHash),
			)
			continue
		}

		mmrSize, err = mc.AddIndexedEntry(leafHash)
		if errors.Is(err, massifs.ErrMassifFull) {
			if err = massifs.CommitContext(ctx, store, &mc); err != nil {
				return &ingress.CommitResult{
					Committed:      committedCount,
					FirstLeafIndex: firstLeafIndex,
				}, fmt.Errorf("commit on massif full: %w", err)
			}
			recordMassifKey(mc.Start.MassifIndex)

			entriesSinceRollover := i - lastCommit
			lastCommit = i
			mc, err = massifs.GetAppendContext(ctx, store, uint32(c.commitmentEpoch), c.massifHeight)
			if err != nil {
				return &ingress.CommitResult{
					Committed:      committedCount,
					FirstLeafIndex: firstLeafIndex,
				}, fmt.Errorf("get append context after rollover: %w", err)
			}

			mmrSize, err = mc.AddIndexedEntry(leafHash)
			if err == nil {
				c.logNotice(ctx,
					"committed (massif full)",
					"logId", logIDHex,
					"mmrSize", mmrSize,
					"count", entriesSinceRollover,
				)
			}
		}
		if err != nil {
			c.logger.Warn("failed to add leaf",
				"logId", logIDHex,
				"index", i,
				"error", err,
			)
			continue
		}

		// AddIndexedEntry returns MMR size (node count) after the append. Derive the
		// zero-based leaf index e for ingress ack / resolveContent (cheatsheet e),
		// not mmr.LeafIndex(mmrNodeIndex).
		leafIndex := mmr.LeafCount(mmrSize) - 1
		if firstLeafIndex == ^uint64(0) {
			firstLeafIndex = leafIndex
		}

		if err := mc.IndexLeaf(idTimestamp, entry.ContentHash); err != nil {
			return &ingress.CommitResult{
				Committed:      committedCount,
				FirstLeafIndex: firstLeafIndex,
			}, fmt.Errorf("update v2 index: %w", err)
		}

		mc.SetLastIDTimestamp(idTimestamp)
		committedCount++
	}

	if err := massifs.CommitContext(ctx, store, &mc); err != nil {
		return &ingress.CommitResult{
			Committed:      committedCount,
			FirstLeafIndex: firstLeafIndex,
		}, fmt.Errorf("final commit: %w", err)
	}
	if committedCount > 0 {
		recordMassifKey(mc.Start.MassifIndex)
	}
	c.logNotice(ctx,
		"committed",
		"logId", logIDHex,
		"mmrSize", mmrSize,
		"count", committedCount,
		"firstLeafIndex", firstLeafIndex,
	)

	return &ingress.CommitResult{
		Committed:        committedCount,
		FirstLeafIndex:   firstLeafIndex,
		MassifObjectKeys: massifKeys,
	}, nil
}

func (c *Committer) logNotice(ctx context.Context, msg string, args ...any) {
	c.logger.Log(ctx, ranger.LevelNotice, msg, args...)
}
