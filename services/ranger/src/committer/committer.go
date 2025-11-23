package committer

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/forestrie/arbor/services/ranger"
	"github.com/forestrie/arbor/services/ranger/consumer"
	"github.com/forestrie/arbor/services/ranger/storage"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/massifs/snowflakeid"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Committer implements MassifCommitter for batch processing messages into merklelog.
type Committer struct {
	factory *storage.Factory

	idState         *snowflakeid.IDState
	logger          *slog.Logger
	massifHeight    uint8
	commitmentEpoch uint32
	trustCanopy     bool
}

// NewCommitter creates a new Committer instance backed by the S3-compatible
// storage backend. This is primarily used in integration tests where MinIO
// provides an S3 API.
func NewCommitter(cfg ranger.Config, httpClient *ranger.HTTPClient, logger *slog.Logger) (*Committer, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("http client is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	factory, err := storage.NewS3Factory(cfg.R2WriteURL, cfg.R2WriterToken, httpClient, logger)
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

	massifHeight := cfg.MassifHeight
	if massifHeight == 0 {
		massifHeight = 14 // Default
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

// NewR2Committer creates a new Committer instance backed by the native R2
// HTTP/JSON backend. This is used by the ranger service in production.
func NewR2Committer(cfg ranger.Config, httpClient *ranger.HTTPClient, logger *slog.Logger) (*Committer, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("http client is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	factory, err := storage.NewR2Factory(cfg.R2WriteURL, cfg.R2WriterToken, httpClient, logger)
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

	massifHeight := cfg.MassifHeight
	if massifHeight == 0 {
		massifHeight = 14 // Default
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

// nextIDTimestampWithRetry wraps the underlying snowflake ID generator so that
// if the generator is temporarily overloaded, we sleep for a minimal interval
// and retry once. If the second attempt fails, that error is returned.
func (c *Committer) nextIDTimestampWithRetry(ctx context.Context) (uint64, error) {
	idTimestamp, err := c.idState.NextID()
	if err == nil {
		return idTimestamp, nil
	}

	if !errors.Is(err, snowflakeid.ErrOverloaded) {
		return 0, err
	}

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(time.Millisecond):
	}

	return c.idState.NextID()
}

// ProcessBatch processes messages belonging to a single logID span.
func (c *Committer) ProcessBatch(
	ctx context.Context,
	batch *consumer.QueuePullResult,
	start, end int,
) (int, error) {
	var mmrIndex uint64
	var leafHash []byte
	var parsed consumer.ParsedNotification

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

	for i := start; i < end; i++ {
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

		idTimestamp, err := c.nextIDTimestampWithRetry(ctx)
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
		leafHash = hasher.Sum(nil)

		if len(leafHash) != massifs.ValueBytes {
			err := fmt.Errorf("invalid leaf hash length %d", len(leafHash))
			batch.Errs[msgIdx] = err
			// Non-retryable validation error - consume the message
			continue
		}

		mmrIndex, err = mc.AddHashedLeaf(
			sha256.New(),
			idTimestamp,
			idTimestampBytes,
			parsed.LogID,
			parsed.Hash,
			leafHash,
		)
		if errors.Is(err, massifs.ErrMassifFull) {
			// Commit the current massif; all items up to and including i are now
			// durably recorded. lastCommit tracks the ByLogID index of the first
			// uncommitted item.
			if err = massifs.CommitContext(ctx, store, &mc); err != nil {
				batch.Errs[msgIdx] = err
				return lastCommit, err
			}
			c.logger.Info(
				"committed",
				"index", mmrIndex,
				"content", fmt.Sprintf("%x", parsed.Hash),
				"leaf", fmt.Sprintf("%x", leafHash))

			lastCommit = i + 1
			mc, err = massifs.GetAppendContext(ctx, store, uint32(c.commitmentEpoch), c.massifHeight)
			if err != nil {
				return lastCommit, fmt.Errorf("failed to get append context after rollover: %w", err)
			}
			_, err = mc.AddHashedLeaf(
				sha256.New(),
				idTimestamp,
				idTimestampBytes,
				parsed.LogID,
				parsed.Hash,
				leafHash,
			)
			// fall through to handle err below
		}
		if err != nil {
			leafErr := fmt.Errorf("failed to add leaf: %w", err)
			batch.Errs[msgIdx] = leafErr
			// all transient errors have been considered above, so consume the
			// message
			continue
		}
	}

	// Final commit of any remaining uncommitted items in this range.
	if err := massifs.CommitContext(ctx, store, &mc); err != nil {
		return lastCommit, err
	}
	c.logger.Info(
		"committed",
		"index", mmrIndex,
		"content", fmt.Sprintf("%x", parsed.Hash),
		"leaf", fmt.Sprintf("%x", leafHash))

	return end, nil
}
