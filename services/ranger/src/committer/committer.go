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
	"github.com/forestrie/arbor/services/ranger/consumer"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/massifs/snowflakeid"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Committer implements MassifCommitter for batch processing messages into merklelog.
type Committer struct {
	factory *merklelog.Factory

	idState         *snowflakeid.IDState
	logger          *slog.Logger
	massifHeight    uint8
	commitmentEpoch uint32
	trustCanopy     bool
}

// NewCommitter creates a new Committer instance backed by the S3-compatible
// storage backend. This is used for both production (Cloudflare R2) and
// integration tests (MinIO). The S3 factory includes x-amz-content-sha256
// header by default for Cloudflare R2 compatibility.
func NewCommitter(cfg ranger.Config, httpClient *ranger.HTTPClient, logger *slog.Logger) (*Committer, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("http client is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	massifHeight := cfg.MassifHeight
	if massifHeight == 0 {
		massifHeight = 14 // Default
	}

	// Use S3 factory with SigV4 signing enabled (required for Cloudflare R2 S3-compatible API).
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
		trustCanopy:     cfg.TrustCanopy,
	}, nil
}


// logNotice logs a message at the NOTICE level (between INFO and WARN).
// When the logger level is set to NOTICE, it excludes INFO and below, but includes WARN and ERROR.
func (c *Committer) logNotice(ctx context.Context, msg string, args ...any) {
	c.logger.Log(ctx, ranger.LevelNotice, msg, args...)
}

// ProcessBatch processes messages belonging to a single logID span.
func (c *Committer) ProcessBatch(
	ctx context.Context,
	batch *consumer.QueuePullResult,
	start, end int,
) (int, error) {
	var mmrIndex uint64
	var parsed consumer.ProcessedNotification

	if start >= end {
		return start, nil
	}

	if start < 0 || end > len(batch.Messages) {
		return start, fmt.Errorf("invalid batch range start=%d end=%d size=%d", start, end, len(batch.ByLogID))
	}

	firstIdx := batch.ByLogID[start]
	parsed = batch.Decoded[firstIdx]
	if len(parsed.LogID) == 0 {
		err := fmt.Errorf("missing logID for message index %d", firstIdx)
		batch.Errs[firstIdx] = err
		return start, err
	}

	logID := massifstorage.LogID(parsed.LogID)
	logIDHex := fmt.Sprintf("%x", parsed.LogID)

	// Each ProcessBatch call uses its own Store instance bound to this log ID.
	store, err := c.factory.NewStore(logID)
	if err != nil {
		return start, fmt.Errorf("failed to create store for log %s: %w", logIDHex, err)
	}

	if err := store.SelectLog(ctx, logID); err != nil {
		return start, fmt.Errorf("failed to select log %s: %w", logIDHex, err)
	}

	mc, err := massifs.GetAppendContext(ctx, store, uint32(c.commitmentEpoch), c.massifHeight)
	if err != nil {
		return start, fmt.Errorf("failed to get append context: %w", err)
	}

	// lastCommit is a ByLogID index and is treated as an exclusive upper bound
	// for messages that have been fully processed and committed.
	lastCommit := start
	i := start

	for ; i < end; i++ {
		msgIdx := batch.ByLogID[i]
		if batch.Errs[msgIdx] != nil {
			continue
		}

		parsed = batch.Decoded[msgIdx]
		if len(parsed.Hash) != sha256.Size {
			err := fmt.Errorf("invalid hash length %d", len(parsed.Hash))
			batch.Errs[msgIdx] = err
			continue
		}

		idTimestamp, err := mc.NextIDTimestamp(ctx, c.idState)
		if err != nil {
			err = fmt.Errorf("failed to generate id timestamp: %w", err)
			batch.Errs[msgIdx] = err
			continue
		}

		idTimestampBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(idTimestampBytes, idTimestamp)

		hasher := sha256.New()
		hasher.Write(idTimestampBytes)
		hasher.Write(parsed.Hash)
		leafHash := hasher.Sum(nil)

		if len(leafHash) != massifs.ValueBytes {
			err := fmt.Errorf("invalid leaf hash length %d", len(leafHash))
			batch.Errs[msgIdx] = err
			// Non-retryable validation error - consume the message
			continue
		}

		mmrIndex, err = mc.AddIndexedEntry(leafHash)
		if errors.Is(err, massifs.ErrMassifFull) {
			// Commit the current massif; all items up to and including i are now
			// durably recorded. lastCommit tracks the ByLogID index of the first
			// uncommitted item.
			if err = massifs.CommitContext(ctx, store, &mc); err != nil {
				batch.Errs[msgIdx] = err
				return lastCommit, err
			}
			c.logNotice(ctx,
				"committed",
				"index", mmrIndex,
				"count", lastCommit-i+1,
				"content", fmt.Sprintf("%x", parsed.Hash),
				"leaf", fmt.Sprintf("%x", leafHash))

			lastCommit = i
			mc, err = massifs.GetAppendContext(ctx, store, uint32(c.commitmentEpoch), c.massifHeight)
			if err != nil {
				return lastCommit, fmt.Errorf("failed to get append context after rollover: %w", err)
			}

			mmrIndex, err = mc.AddIndexedEntry(leafHash)
			// fall through to handle err below
		}
		if err != nil {
			leafErr := fmt.Errorf("failed to add leaf: %w", err)
			batch.Errs[msgIdx] = leafErr
			// all transient errors have been considered above, so consume the
			// message
			continue
		}

		// Update the v2 index structures (Urkle + Bloom) corresponding to the leaf we just appended.
		// Note: IndexLeaf stores parsed.Hash (content-hash) directly in the trie valueBytes,
		// not the MMR leaf hash H(idtimestamp || content-hash). This enables direct verification
		// of (idtimestamp, content) pair exclusion without needing to check the MMR structure.
		if err := mc.IndexLeaf(idTimestamp, parsed.Hash); err != nil {
			leafErr := fmt.Errorf("failed to update v2 index: %w", err)
			batch.Errs[msgIdx] = leafErr
			return lastCommit, leafErr
		}

		// Update the massif header's last id timestamp.
		mc.SetLastIDTimestamp(idTimestamp)
	}

	// Final commit of any remaining uncommitted items in this range.
	if err := massifs.CommitContext(ctx, store, &mc); err != nil {
		return lastCommit, err
	}
	c.logNotice(ctx,
		"committed",
		"index", mmrIndex,
		"count", lastCommit-(i-1))

	return end, nil
}
