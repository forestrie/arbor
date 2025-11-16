package committer

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

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

// NewCommitter creates a new Committer instance.
func NewCommitter(cfg ranger.Config, httpClient *ranger.HTTPClient, logger *slog.Logger) (*Committer, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("http client is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Create storage factory; individual stores will be instantiated per-log.
	factory, err := storage.NewFactory(cfg.R2WriteURL, cfg.R2WriterToken, httpClient, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage factory: %w", err)
	}

	// Initialize IDState with commitmentEpoch
	// Use reasonable defaults for WorkerCIDR and PodIP
	// These can be made configurable later if needed
	idState, err := snowflakeid.NewIDState(snowflakeid.Config{
		CommitmentEpoch: uint8(cfg.CommitmentEpoch),
		WorkerCIDR:      "0.0.0.0/16", // Default CIDR
		PodIP:           "10.0.0.1",   // Default pod IP
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

// ProcessBatch processes messages belonging to a single logID span.
func (c *Committer) ProcessBatch(
	ctx context.Context,
	batch *consumer.QueuePullResult,
	start, end int,
) error {
	if start >= end {
		return nil
	}

	if start < 0 || end > len(batch.Messages) {
		return fmt.Errorf("invalid batch range start=%d end=%d size=%d", start, end, len(batch.ByLogID))
	}

	firstIdx := batch.ByLogID[start]
	parsed := batch.Decoded[firstIdx]
	if len(parsed.LogID) == 0 {
		err := fmt.Errorf("missing logID for message index %d", firstIdx)
		batch.Errs[firstIdx] = err
		return err
	}

	logID := massifstorage.LogID(parsed.LogID)
	logIDHex := fmt.Sprintf("%x", parsed.LogID)

	// Each ProcessBatch call uses its own Store instance bound to this log ID.
	store, err := c.factory.NewStore(logID)
	if err != nil {
		rangeErr := fmt.Errorf("failed to create store for log %s: %w", logIDHex, err)
		for i := start; i < end; i++ {
			batch.Errs[batch.ByLogID[i]] = rangeErr
		}
		return rangeErr
	}

	if err := store.SelectLog(ctx, logID); err != nil {
		rangeErr := fmt.Errorf("failed to select log %s: %w", logIDHex, err)
		for i := start; i < end; i++ {
			batch.Errs[batch.ByLogID[i]] = rangeErr
		}
		return rangeErr
	}

	mc, err := massifs.GetAppendContext(ctx, store, uint32(c.commitmentEpoch), c.massifHeight)
	if err != nil {
		rangeErr := fmt.Errorf("failed to get append context: %w", err)
		for i := start; i < end; i++ {
			batch.Errs[batch.ByLogID[i]] = rangeErr
		}
		return rangeErr
	}

	committed := make([]int, 0, end-start)

	commitRange := func(afterRollover bool) error {
		if len(committed) > 0 {
			if err := massifs.CommitContext(ctx, store, &mc); err != nil {
				commitErr := fmt.Errorf("failed to commit context: %w", err)
				for _, idx := range committed {
					batch.Errs[idx] = commitErr
				}
				return commitErr
			}

			for _, idx := range committed {
				batch.Ack[idx] = true
				batch.Errs[idx] = nil
			}
			committed = committed[:0]
		}

		if afterRollover {
			var getErr error
			mc, getErr = massifs.GetAppendContext(ctx, store, uint32(c.commitmentEpoch), c.massifHeight)
			if getErr != nil {
				return fmt.Errorf("failed to get append context after rollover: %w", getErr)
			}
		}

		return nil
	}

	for i := start; i < end; i++ {
		msgIdx := batch.ByLogID[i]
		if batch.Errs[msgIdx] != nil {
			continue
		}

		parsed := batch.Decoded[msgIdx]
		if len(parsed.Hash) != sha256.Size {
			err := fmt.Errorf("invalid hash length %d", len(parsed.Hash))
			batch.Errs[msgIdx] = err
			// Non-retryable validation error - consume the message
			batch.Ack[msgIdx] = true
			c.logger.Warn("invalid hash length",
				"logID", logIDHex,
				"fenceIndex", parsed.FenceIndex,
				"length", len(parsed.Hash),
			)
			continue
		}

		idTimestamp, err := c.idState.NextID()
		if err != nil {
			err = fmt.Errorf("failed to generate id timestamp: %w", err)
			batch.Errs[msgIdx] = err
			c.logger.Warn("failed to generate id timestamp",
				"logID", logIDHex,
				"fenceIndex", parsed.FenceIndex,
				"error", err,
			)
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
			batch.Ack[msgIdx] = true
			c.logger.Warn("invalid leaf hash length",
				"logID", logIDHex,
				"fenceIndex", parsed.FenceIndex,
				"length", len(leafHash),
			)
			continue
		}

		for {
			_, err = mc.AddHashedLeaf(
				sha256.New(),
				idTimestamp,
				idTimestampBytes,
				parsed.LogID,
				parsed.Hash,
				leafHash,
			)
			if errors.Is(err, massifs.ErrMassifFull) {
				if commitErr := commitRange(true); commitErr != nil {
					batch.Errs[msgIdx] = commitErr
					return commitErr
				}
				continue
			}
			if err != nil {
				leafErr := fmt.Errorf("failed to add leaf: %w", err)
				batch.Errs[msgIdx] = leafErr
				c.logger.Warn("failed to add leaf",
					"logID", logIDHex,
					"fenceIndex", parsed.FenceIndex,
					"error", err,
				)
			} else {
				committed = append(committed, msgIdx)
			}
			break
		}
	}

	if err := commitRange(false); err != nil {
		return err
	}

	return nil
}
