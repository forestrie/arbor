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

	// No default here: the consumer acks with cfg.MassifHeight, so the
	// committer must write at exactly that height (see Config.Validate).
	massifHeight := cfg.MassifHeight
	if massifHeight < 1 || massifHeight > 64 {
		return nil, fmt.Errorf("massif height must be 1..64, got %d", massifHeight)
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
// It commits every entry or returns an error: on error the result is nil and
// the caller must not ack. On success the CommitResult carries the count
// (always len(entries)) and the first leaf index, which the consumer acks
// with.
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

	// Any failure returns an error and a nil result, so the consumer does not
	// ack and the whole batch redelivers. Never skip an entry: the
	// forestrie-ingress ack is limit-based (row i gets leaf F+i), so a skip
	// shifts every later row onto the wrong leaf (FOR-653). A failure after a
	// mid-batch rollover leaves that massif written; the redelivery appends
	// the batch again and is acked onto those leaves, so the earlier copies
	// are unreferenced duplicates. That costs leaves only on the failure path.
	for i, entry := range entries {
		if len(entry.ContentHash) != sha256.Size {
			return nil, fmt.Errorf("entry %d of log %s: content hash is %d bytes, want %d",
				i, logIDHex, len(entry.ContentHash), sha256.Size)
		}

		idTimestamp, err := mc.NextIDTimestamp(ctx, c.idState)
		if err != nil {
			return nil, fmt.Errorf("entry %d of log %s: id timestamp: %w", i, logIDHex, err)
		}

		// The leaf binds the index it is stored at, so it is built from the
		// context that takes it, here and again after a rollover. Rolled
		// forward in memory, the next massif starts where the full one
		// ended, so both give the same index.
		mmrSize, err = mc.AddIndexedEntry(leafHash(mc.RangeCount(), idTimestamp, entry.ContentHash))
		if errors.Is(err, massifs.ErrMassifFull) {
			if err = massifs.CommitContext(ctx, store, &mc); err != nil {
				return nil, fmt.Errorf("commit on massif full: %w", err)
			}
			recordMassifKey(mc.Start.MassifIndex)

			entriesSinceRollover := i - lastCommit
			lastCommit = i
			// Roll the committed context forward in memory rather than
			// re-reading the head massif. The batch must occupy contiguous
			// leaves (limit-based ack, FOR-653); a re-read would pick up a
			// massif another ranger created in the meantime and append after
			// its leaves. Rolled forward, the new massif is created
			// If-None-Match (FOR-656), so that ranger's massif fails this
			// batch instead.
			if err = massifs.InitAppendContext(ctx, store, &mc); err != nil {
				return nil, fmt.Errorf("start next massif after rollover: %w", err)
			}

			mmrSize, err = mc.AddIndexedEntry(leafHash(mc.RangeCount(), idTimestamp, entry.ContentHash))
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
			return nil, fmt.Errorf("entry %d of log %s: add leaf: %w", i, logIDHex, err)
		}

		// AddIndexedEntry returns MMR size (node count) after the append. Derive the
		// zero-based leaf index e for ingress ack / resolveContent (cheatsheet e),
		// not mmr.LeafIndex(mmrNodeIndex).
		leafIndex := mmr.LeafCount(mmrSize) - 1
		if firstLeafIndex == ^uint64(0) {
			firstLeafIndex = leafIndex
		}

		if err := mc.IndexLeaf(idTimestamp, entry.ContentHash); err != nil {
			return nil, fmt.Errorf("update v2 index: %w", err)
		}

		mc.SetLastIDTimestamp(idTimestamp)
		committedCount++
	}

	if err := massifs.CommitContext(ctx, store, &mc); err != nil {
		return nil, fmt.Errorf("final commit: %w", err)
	}
	recordMassifKey(mc.Start.MassifIndex)
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

// leafHash returns the MMR leaf for an entry stored at mmrIndex, in the form
// proposed for the COSE Receipts MMR profile (FOR-726, "option D"; see
// ietf-wg-scitt/draft-ietf-scitt-receipts-mmr-profile#69):
//
//	H(0x00 || pos || H(tsLeafData) || contentHash), pos = mmrIndex + 1
//
// tsLeafData = 0x01 || idTimestamp is Forestrie's transparency service
// contribution. pos and the idtimestamp are 8 bytes big-endian, as pos is
// for interior nodes. The leading 0x00 and the 73-byte pre-image keep a
// leaf distinct from an interior node's 72-byte pos || left || right.
func leafHash(mmrIndex, idTimestamp uint64, contentHash []byte) []byte {
	var tsLeafData [9]byte
	tsLeafData[0] = 0x01
	binary.BigEndian.PutUint64(tsLeafData[1:], idTimestamp)
	tsLeafDataHash := sha256.Sum256(tsLeafData[:])

	hasher := sha256.New()
	hasher.Write([]byte{0x00})
	mmr.HashWriteUint64(hasher, mmrIndex+1)
	hasher.Write(tsLeafDataHash[:])
	hasher.Write(contentHash)
	return hasher.Sum(nil)
}

func (c *Committer) logNotice(ctx context.Context, msg string, args ...any) {
	c.logger.Log(ctx, ranger.LevelNotice, msg, args...)
}
