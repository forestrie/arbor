package committer

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
	store           *storage.Store
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

	// Create storage factory and store (without initial logID)
	factory, err := storage.NewFactory(cfg.R2WriteURL, cfg.R2WriterToken, httpClient, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage factory: %w", err)
	}

	// Create store without initial logID - we'll select logs as needed
	store, err := factory.NewStore(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
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
		store:           store,
		idState:         idState,
		logger:          logger,
		massifHeight:    massifHeight,
		commitmentEpoch: cfg.CommitmentEpoch,
		trustCanopy:     cfg.TrustCanopy,
	}, nil
}

// ProcessBatch processes a batch of messages and commits them to the merklelog.
// It returns the count of successfully acknowledged messages.
// This implements the consumer.MassifCommitter interface.
func (c *Committer) ProcessBatch(
	ctx context.Context,
	messages []consumer.MessageWithNotification,
	acker consumer.MessageAcker,
) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}

	// Messages are assumed to be pre-sorted by logID (via object key sorting in processBatchWithCommitter)
	// Track acknowledged count
	acknowledged := 0

	// Process messages grouped by logID
	currentLogID := ""
	var currentBatch []consumer.MessageWithNotification

	for i, msgWithNotif := range messages {
		// Start new batch when logID changes
		if msgWithNotif.Parsed.LogID != currentLogID {
			// Process previous batch if exists
			if len(currentBatch) > 0 {
				count, err := c.processLogBatch(ctx, currentBatch, acker)
				// Always accumulate count, even if there was an error, since some messages
				// may have been successfully processed and acknowledged before the error occurred
				acknowledged += count
				if err != nil {
					c.logger.Error("failed to process log batch",
						"logID", currentLogID,
						"acknowledged", count,
						"error", err,
					)
					// Continue with next batch even if this one failed
				}
			}

			// Start new batch
			currentLogID = msgWithNotif.Parsed.LogID
			currentBatch = []consumer.MessageWithNotification{msgWithNotif}
		} else {
			currentBatch = append(currentBatch, msgWithNotif)
		}

		// Process last batch
		if i == len(messages)-1 {
			count, err := c.processLogBatch(ctx, currentBatch, acker)
			// Always accumulate count, even if there was an error, since some messages
			// may have been successfully processed and acknowledged before the error occurred
			acknowledged += count
			if err != nil {
				c.logger.Error("failed to process log batch",
					"logID", currentLogID,
					"acknowledged", count,
					"error", err,
				)
			}
		}
	}

	return acknowledged, nil
}

// processLogBatch processes all messages for a single logID.
func (c *Committer) processLogBatch(
	ctx context.Context,
	messages []consumer.MessageWithNotification,
	acker consumer.MessageAcker,
) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}

	logID := massifstorage.LogID([]byte(messages[0].Parsed.LogID))

	// Select the log
	if err := c.store.SelectLog(ctx, logID); err != nil {
		return 0, fmt.Errorf("failed to select log %s: %w", messages[0].Parsed.LogID, err)
	}

	// Get append context
	mc, err := massifs.GetAppendContext(
		ctx, c.store,
		uint32(c.commitmentEpoch), c.massifHeight)
	if err != nil {
		return 0, fmt.Errorf("failed to get append context: %w", err)
	}

	// Track indices of successfully committed messages (more efficient than copying structs)
	committedIndices := []int{}
	// Track total acknowledged count across all massif rollovers
	totalAcknowledged := 0

	// Process each message
	for i, msgWithNotif := range messages {
		msg := msgWithNotif.Parsed
		// Extract hash from ParsedNotification.Hash (64-char hex)
		contentHash, err := hex.DecodeString(msg.Hash)
		if err != nil {
			c.logger.Warn("failed to decode hash",
				"logID", msg.LogID,
				"hash", msg.Hash,
				"error", err,
			)
			continue
		}

		if len(contentHash) != 32 {
			c.logger.Warn("invalid hash length",
				"logID", msg.LogID,
				"hash", msg.Hash,
				"length", len(contentHash),
			)
			continue
		}

		// Get idtimestamp from idState
		idTimestamp, err := c.idState.NextID()
		if err != nil {
			c.logger.Warn("failed to generate id timestamp",
				"logID", msg.LogID,
				"error", err,
			)
			continue
		}

		// Compute leaf hash: sha256(idtimestamp || contentHash)
		hasher := sha256.New()
		idTimestampBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(idTimestampBytes, idTimestamp)
		hasher.Write(idTimestampBytes)
		hasher.Write(contentHash)
		leafHash := hasher.Sum(nil)

		if len(leafHash) != massifs.ValueBytes {
			c.logger.Warn("invalid leaf hash length",
				"logID", msg.LogID,
				"length", len(leafHash),
			)
			continue
		}

		// Convert logID string to bytes
		logIDBytes := []byte(msg.LogID)
		// Use the original content hash as the appID
		appID := contentHash

		// Add leaf to context
		_, err = mc.AddHashedLeaf(
			sha256.New(),
			idTimestamp,
			idTimestampBytes, // include the bytes of idtimestamp as extraBytes
			logIDBytes,
			appID,
			leafHash,
		)

		if errors.Is(err, massifs.ErrMassifFull) {
			// Commit current context
			if err := massifs.CommitContext(ctx, c.store, &mc); err != nil {
				// Commit failed - messages weren't persisted, so don't acknowledge them
				// Return 0 since nothing was successfully committed in this batch
				return 0, fmt.Errorf("failed to commit context: %w", err)
			}

			// Commit succeeded - acknowledge messages that were just successfully committed
			acknowledgedCount := 0
			stillPendingIndices := []int{}
			for _, idx := range committedIndices {
				msgWithNotif := messages[idx]
				if ackErr := acker(ctx, msgWithNotif.Message); ackErr != nil {
					c.logger.Warn("failed to acknowledge message after massif commit",
						"messageID", msgWithNotif.Message.ID,
						"logID", msgWithNotif.Parsed.LogID,
						"error", ackErr,
					)
					// Keep index for retry at the end
					stillPendingIndices = append(stillPendingIndices, idx)
				} else {
					acknowledgedCount++
				}
			}

			// Get new append context
			mc, err = massifs.GetAppendContext(
				ctx, c.store,
				uint32(c.commitmentEpoch), c.massifHeight)
			if err != nil {
				// Messages were already committed, some were acknowledged
				// This is a critical error - we can't continue processing without a context
				// Log the error and return partial results
				// Remaining messages in the batch will remain in the queue and be retried
				c.logger.Error("failed to get new append context after rollover - stopping batch processing",
					"logID", msg.LogID,
					"processed", len(committedIndices),
					"acknowledged", totalAcknowledged+acknowledgedCount,
					"remaining", len(messages)-i-1,
					"error", err,
				)
				// Return count of acknowledged messages and error indicating partial processing
				return totalAcknowledged + acknowledgedCount, fmt.Errorf("failed to get new append context after rollover (processed %d/%d messages): %w", i+1, len(messages), err)
			}

			// Accumulate acknowledged count from this rollover
			totalAcknowledged += acknowledgedCount

			// Keep only indices of messages that failed acknowledgment for retry at the end
			// The current message index will be added to committedIndices after retry
			committedIndices = stillPendingIndices

			// Retry adding the leaf with the same extraBytes for consistency
			_, err = mc.AddHashedLeaf(
				sha256.New(),
				idTimestamp,
				idTimestampBytes, // Use same extraBytes as initial call for consistency
				logIDBytes,
				appID,
				leafHash,
			)
			if err != nil {
				c.logger.Warn("failed to add leaf after massif rollover",
					"logID", msg.LogID,
					"error", err,
				)
				continue
			}
		} else if err != nil {
			c.logger.Warn("failed to add leaf",
				"logID", msg.LogID,
				"error", err,
			)
			continue
		}

		// Track successfully added message index
		committedIndices = append(committedIndices, i)
	}

	// Commit final context
	if len(committedIndices) > 0 {
		if err := massifs.CommitContext(ctx, c.store, &mc); err != nil {
			// Commit failed - messages were added to context but not persisted
			// Return len(committedIndices) to indicate how many were processed,
			// but don't acknowledge them since they weren't committed
			return len(committedIndices), fmt.Errorf("failed to commit final context: %w", err)
		}
	}

	// Acknowledge all successfully committed messages
	acknowledged := 0
	for _, idx := range committedIndices {
		msgWithNotif := messages[idx]
		if err := acker(ctx, msgWithNotif.Message); err != nil {
			c.logger.Warn("failed to acknowledge message",
				"messageID", msgWithNotif.Message.ID,
				"logID", msgWithNotif.Parsed.LogID,
				"error", err,
			)
			// Continue acknowledging other messages even if one fails
			continue
		}
		acknowledged++
	}

	// Return total acknowledged count including messages acknowledged during rollovers
	return totalAcknowledged + acknowledged, nil
}
