// Notification-loss backstop (plan-2607-07 R1, FOR-408).
//
// The publisher queue is fed by R2 event notifications, and every other
// recovery path (ADR-0008 catch-up, the plan-2607-06 in-cycle drain)
// presupposes that a message for the checkpoint eventually arrives. On
// 2026-07-19 the notifications for two fresh forests' genesis checkpoints
// were never delivered, permanently stranding both forests behind the
// hierarchical owner-gate. This sweep is the publisher-side twin of the
// sealer's resync.go: list the sealed checkpoints from R2 and re-drive the
// one-shot publish for anything not yet anchored — in-process, never by
// publishing to its own queue. A lost notification becomes a delay of at
// most one sweep interval instead of a permanent strand.
package publisher

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
)

// CheckpointsPrefix is the R2 object prefix the queue is notified on and the
// sweep lists.
const CheckpointsPrefix = "v2/merklelog/checkpoints/"

// resyncMaxPasses bounds the owner-ordering fixpoint within one sweep: pass 1
// anchors roots, pass 2 the children they unblock, and so on. A forest deeper
// than this simply completes over subsequent sweeps.
const resyncMaxPasses = 4

// oneShotPublisher is the slice of *Publisher the sweep drives (the same
// synchronous core as the `publisher publish` CLI). Interface for tests.
type oneShotPublisher interface {
	Publish(ctx context.Context, key string) (PublishResult, error)
}

// objectLister lists checkpoint objects. *s3.Client satisfies it.
type objectLister interface {
	ListObjects(ctx context.Context, prefix, continuationToken string, maxKeys int) (s3.ListResult, error)
}

// ResyncMetrics is the metrics slice the sweep records to; nil-safe via
// noopResyncMetrics.
type ResyncMetrics interface {
	// RecordResyncGap counts a checkpoint anchored by the sweep — i.e. a
	// notification the queue never delivered (R3 "notification loss").
	RecordResyncGap()
	// RecordResyncSweep counts a completed sweep by result ("ok" | "error").
	RecordResyncSweep(result string)
}

type noopResyncMetrics struct{}

func (noopResyncMetrics) RecordResyncGap()         {}
func (noopResyncMetrics) RecordResyncSweep(string) {}

// SweepStats summarises one sweep.
type SweepStats struct {
	// Listed is the number of candidate .sth keys after per-log coalescing.
	Listed int
	// Gaps is the number of checkpoints the sweep anchored (lost
	// notifications, or checkpoints whose messages died on the retry cliff).
	Gaps int
	// Covered counts checkpoints already anchored (the healthy steady state).
	Covered int
	// Blocked counts checkpoints still owner-gated at sweep end (their owner
	// did not anchor this sweep; retried next interval).
	Blocked int
	// Errors counts keys abandoned this sweep on infrastructure errors.
	Errors int
}

// Resync periodically reconciles sealed checkpoints against on-chain state.
type Resync struct {
	pub      oneShotPublisher
	lister   objectLister
	interval time.Duration
	pageSize int
	logger   *slog.Logger
	metrics  ResyncMetrics
}

// NewResync wires the sweep from config. The publish core is shared with the
// queue consumer — Publish is idempotent (a concurrent duplicate resolves as
// already-anchored on the fresh logState read), so the two paths can overlap
// safely. Returns nil when RESYNC_INTERVAL is unset/zero (backstop disabled).
func NewResync(cfg Config, pub *Publisher, doer s3.HTTPDoer, logger *slog.Logger, m ResyncMetrics) (*Resync, error) {
	if cfg.ResyncInterval <= 0 {
		return nil, nil
	}
	lister, err := s3.NewClientWithCredentials(
		cfg.R2URL, cfg.R2Token,
		cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, cfg.AWSRegion,
		doer, logger,
	)
	if err != nil {
		return nil, err
	}
	if m == nil {
		m = noopResyncMetrics{}
	}
	return &Resync{
		pub:      pub,
		lister:   lister,
		interval: cfg.ResyncInterval,
		pageSize: cfg.ResyncPageSize,
		logger:   logger,
		metrics:  m,
	}, nil
}

// Run sweeps once at startup and then every interval until ctx is cancelled.
func (r *Resync) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		stats, err := r.SweepOnce(ctx)
		if err != nil {
			r.metrics.RecordResyncSweep("error")
			r.logger.Warn("resync sweep failed", "error", err)
		} else {
			r.metrics.RecordResyncSweep("ok")
			if stats.Gaps > 0 || stats.Blocked > 0 || stats.Errors > 0 {
				r.logger.Warn("resync sweep",
					"listed", stats.Listed, "gaps", stats.Gaps, "covered", stats.Covered,
					"blocked", stats.Blocked, "errors", stats.Errors)
			} else {
				r.logger.Info("resync sweep clean", "listed", stats.Listed)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// SweepOnce lists every checkpoint under CheckpointsPrefix, coalesces to the
// highest massif index per log (the anchored highest seal subsumes lower
// massifs via the consistency chain, mirroring the consumer's coalesce), and
// re-drives the one-shot publish for each. Owner-gated checkpoints are
// retried in root-first passes: anchoring a genesis in pass N unblocks its
// children in pass N+1.
func (r *Resync) SweepOnce(ctx context.Context) (SweepStats, error) {
	var stats SweepStats

	keys, err := r.listCheckpointKeys(ctx)
	if err != nil {
		return stats, err
	}
	stats.Listed = len(keys)

	pending := keys
	for pass := 0; pass < resyncMaxPasses && len(pending) > 0; pass++ {
		var blocked []string
		progressed := false
		for _, key := range pending {
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			res, err := r.pub.Publish(ctx, key)
			if err != nil {
				stats.Errors++
				r.logger.Warn("resync publish failed", "key", key, "error", err)
				continue
			}
			switch res.Status {
			case StatusPublished:
				stats.Gaps++
				progressed = true
				r.metrics.RecordResyncGap()
				// R3: this checkpoint was sealed but had no live queue message
				// — a lost notification or a dead-lettered dependency chain.
				r.logger.Warn("notification loss detected: checkpoint anchored by resync sweep",
					"key", key, "sealedSize", res.SealedSize, "onchainSize", res.OnchainSize,
					"chain", res.ChainID, "contract", res.Contract.Hex(), "tx", res.TxHash.Hex())
			case StatusAlreadyAnchored:
				stats.Covered++
			case StatusOwnerNotAnchored:
				blocked = append(blocked, key)
			default:
				// Reverted / chain-not-configured / retry: the queue path (or an
				// operator, for config) owns these; the sweep only reports.
				stats.Errors++
				r.logger.Warn("resync skipped checkpoint", "key", key,
					"status", res.Status.String(), "reason", res.Reason)
			}
		}
		pending = blocked
		if !progressed {
			break
		}
	}
	stats.Blocked = len(pending)
	return stats, nil
}

// listCheckpointKeys pages the checkpoints prefix and returns one key per
// (height, log): the highest massif index seen.
func (r *Resync) listCheckpointKeys(ctx context.Context) ([]string, error) {
	type best struct {
		key   string
		index uint32
	}
	latest := make(map[string]best) // "{height}/{uuid}" -> highest-index key

	token := ""
	for {
		page, err := r.lister.ListObjects(ctx, CheckpointsPrefix, token, r.pageSize)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Objects {
			ck, err := ParseCheckpointKey(obj.Key)
			if err != nil {
				continue // not a .sth (or malformed) — not sweep material
			}
			group := fmt.Sprintf("%d/%s", ck.MassifHeight, ck.LogID)
			if cur, ok := latest[group]; !ok || ck.MassifIndex > cur.index {
				latest[group] = best{key: obj.Key, index: ck.MassifIndex}
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		token = page.NextContinuationToken
	}

	keys := make([]string, 0, len(latest))
	for _, b := range latest {
		keys = append(keys, b.key)
	}
	return keys, nil
}
