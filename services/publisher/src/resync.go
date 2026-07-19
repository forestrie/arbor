// Notification-loss backstop (plan-2607-07 R1, FOR-408; hardened per
// plan-2607-08 W1–W3).
//
// The publisher queue is fed by R2 event notifications, and every other
// recovery path (ADR-0008 catch-up, the plan-2607-06 in-cycle drain)
// presupposes that a message for the checkpoint eventually arrives. On
// 2026-07-19 the notifications for two fresh forests' genesis checkpoints
// were never delivered, permanently stranding both forests behind the
// hierarchical owner-gate. This sweep is the publisher-side twin of the
// sealer's resync.go: list the sealed checkpoints from R2 and re-drive the
// publish core for anything not yet anchored — in-process, never by
// publishing to its own queue. A lost notification becomes a delay of at
// most one sweep interval instead of a permanent strand.
//
// Submission goes through SubmitBatch so the batch path's chainNonce stays
// the single nonce authority (plan-2607-08 W1) — the sweep must never call
// ChainWriter.Submit, which bypasses the in-process counter.
package publisher

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
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

// resyncHealthyWithin is the freshness multiple for Healthy(): the consumer
// may ack owner-gated messages only while the last successful sweep is at
// most this many intervals old (plan-2607-08 W2).
const resyncHealthyWithin = 3

// sweepCore is the slice of *Publisher the sweep drives. Deliberately the
// same surface as the consumer's publishCore minus From: Assemble for the
// read phase and SubmitBatch for submission, so nonce management stays with
// chainNonce (W1). There is intentionally no Submit here.
type sweepCore interface {
	Assemble(ctx context.Context, key string) (calldata []byte, res PublishResult, ready bool, err error)
	SubmitBatch(ctx context.Context, reqs []AssembledPublish)
}

// objectLister lists checkpoint objects. *s3.Client satisfies it.
type objectLister interface {
	ListObjects(ctx context.Context, prefix, continuationToken string, maxKeys int) (s3.ListResult, error)
}

// ResyncMetrics is the metrics slice the sweep records to; nil-safe via
// noopResyncMetrics.
type ResyncMetrics interface {
	// RecordResyncGap counts a checkpoint anchored by the sweep whose
	// notification the queue never delivered (R3 "notification loss").
	RecordResyncGap()
	// RecordResyncHandoff counts a checkpoint anchored by the sweep that the
	// consumer deliberately acked as owner-gated (plan-2607-08 W2: the
	// expected handoff, not a delivery fault).
	RecordResyncHandoff()
	// RecordResyncSweep counts a completed sweep by result ("ok" | "error").
	RecordResyncSweep(result string)
}

type noopResyncMetrics struct{}

func (noopResyncMetrics) RecordResyncGap()         {}
func (noopResyncMetrics) RecordResyncHandoff()     {}
func (noopResyncMetrics) RecordResyncSweep(string) {}

// OwnerGateHandoffs is the consumer → sweep channel that keeps the
// "notification loss" signal honest (plan-2607-08 W2/F7): the consumer
// records each checkpoint key it acks as owner-gated; the sweep classifies
// an anchored key found here as a handoff, not a lost notification.
type OwnerGateHandoffs struct {
	mu    sync.Mutex
	byKey map[string]time.Time
}

// ownerGateHandoffsCap bounds the map; beyond it the oldest entries are
// pruned (misclassifying an evicted handoff as a gap only over-alerts).
const ownerGateHandoffsCap = 4096

func NewOwnerGateHandoffs() *OwnerGateHandoffs {
	return &OwnerGateHandoffs{byKey: make(map[string]time.Time)}
}

// Record notes that key was acked as owner-gated now.
func (h *OwnerGateHandoffs) Record(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.byKey) >= ownerGateHandoffsCap {
		oldestKey, oldest := "", time.Time{}
		for k, t := range h.byKey {
			if oldest.IsZero() || t.Before(oldest) {
				oldestKey, oldest = k, t
			}
		}
		delete(h.byKey, oldestKey)
	}
	h.byKey[key] = time.Now()
}

// Recent reports whether key was recorded within maxAge, pruning it either
// way (each handoff explains at most one sweep-anchor).
func (h *OwnerGateHandoffs) Recent(key string, maxAge time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, ok := h.byKey[key]
	if !ok {
		return false
	}
	delete(h.byKey, key)
	return time.Since(t) <= maxAge
}

// SweepStats summarises one sweep.
type SweepStats struct {
	// Listed is the number of logs (coalesced groups) with sealed checkpoints.
	Listed int
	// Gaps counts checkpoints anchored by the sweep with no recorded
	// owner-gate handoff — genuine lost notifications (or dead-lettered
	// dependents from before the sweep existed).
	Gaps int
	// Handoffs counts checkpoints anchored by the sweep that the consumer
	// deliberately acked as owner-gated (the designed division of labour).
	Handoffs int
	// Covered counts checkpoints already anchored (the healthy steady state).
	Covered int
	// Blocked counts logs still owner-gated at sweep end (their owner did not
	// anchor this sweep; retried next interval).
	Blocked int
	// Unpublishable counts seals that mined a revert (poison, FOR-377 shape);
	// lower massifs of the same log are attempted in their place (W3).
	Unpublishable int
	// Errors counts keys abandoned this sweep on infrastructure errors.
	Errors int
}

// logSeals is one log's sealed checkpoint keys, highest massif index first.
// The sweep drives the highest publishable seal; on a poison (reverted) top
// seal it falls back to the next lower massif (plan-2607-08 W3) so a
// publishable prefix is never starved.
type logSeals struct {
	keys []string
	next int // index into keys of the candidate to drive
}

// Resync periodically reconciles sealed checkpoints against on-chain state.
type Resync struct {
	pub      sweepCore
	lister   objectLister
	interval time.Duration
	pageSize int
	logger   *slog.Logger
	metrics  ResyncMetrics
	handoffs *OwnerGateHandoffs

	// lastGood is the unix-nano time of the last successful sweep; Healthy()
	// gates the consumer's owner-gated acks on it (W2).
	lastGood atomic.Int64
}

// NewResync wires the sweep from config. The publish core is shared with the
// queue consumer; both submit through SubmitBatch, so chainNonce remains the
// single nonce authority (W1) and duplicates resolve as already-anchored.
// Returns nil when PUBLISHER_RESYNC_INTERVAL is unset (backstop disabled).
func NewResync(cfg Config, pub *Publisher, doer s3.HTTPDoer, logger *slog.Logger, m ResyncMetrics, handoffs *OwnerGateHandoffs) (*Resync, error) {
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
	if handoffs == nil {
		handoffs = NewOwnerGateHandoffs()
	}
	return &Resync{
		pub:      pub,
		lister:   lister,
		interval: cfg.ResyncInterval,
		pageSize: cfg.ResyncPageSize,
		logger:   logger,
		metrics:  m,
		handoffs: handoffs,
	}, nil
}

// Healthy reports whether the last successful sweep is recent enough for the
// consumer to ack owner-gated messages (W2). False until the first
// successful sweep, so a freshly-enabled (or persistently failing) sweep
// leaves the pre-existing redelivery contract in force.
func (r *Resync) Healthy() bool {
	last := r.lastGood.Load()
	if last == 0 {
		return false
	}
	return time.Since(time.Unix(0, last)) <= resyncHealthyWithin*r.interval
}

// Run sweeps once at startup and then every interval until ctx is cancelled.
func (r *Resync) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		stats, err := r.SweepOnce(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			r.metrics.RecordResyncSweep("error")
			r.logger.Warn("resync sweep failed", "error", err)
		default:
			r.metrics.RecordResyncSweep("ok")
			r.lastGood.Store(time.Now().UnixNano())
			if stats.Gaps > 0 || stats.Blocked > 0 || stats.Errors > 0 || stats.Unpublishable > 0 {
				r.logger.Warn("resync sweep",
					"listed", stats.Listed, "gaps", stats.Gaps, "handoffs", stats.Handoffs,
					"covered", stats.Covered, "blocked", stats.Blocked,
					"unpublishable", stats.Unpublishable, "errors", stats.Errors)
			} else {
				r.logger.Info("resync sweep clean", "listed", stats.Listed, "handoffs", stats.Handoffs)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweepOutcome is one submitted candidate's finalized result.
type sweepOutcome struct {
	group *logSeals
	key   string
	res   PublishResult
}

// SweepOnce lists every checkpoint under CheckpointsPrefix, coalesces per
// (height, log) with keys ordered highest massif first, and re-drives the
// publish core for each log's best publishable seal in root-first passes:
// anchoring a genesis in pass N unblocks its children in pass N+1.
func (r *Resync) SweepOnce(ctx context.Context) (SweepStats, error) {
	var stats SweepStats

	groups, err := r.listLogSeals(ctx)
	if err != nil {
		return stats, err
	}
	stats.Listed = len(groups)

	pending := groups
	for pass := 0; pass < resyncMaxPasses && len(pending) > 0; pass++ {
		var (
			blocked []*logSeals
			ready   []AssembledPublish
			mu      sync.Mutex
			wg      sync.WaitGroup
			results []sweepOutcome
		)

		// Assemble phase: walk each group's candidates top-down until one is
		// submittable, blocked, or the group is exhausted (W3 fallback for
		// assemble-time terminal statuses).
		for _, g := range pending {
			req, outcome, done := r.assembleCandidate(ctx, g, &stats)
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			switch {
			case done:
				// settled at assemble time (covered / errors / exhausted)
			case outcome == StatusOwnerNotAnchored:
				blocked = append(blocked, g)
			default:
				g := g
				key := req.key
				wg.Add(1)
				ready = append(ready, AssembledPublish{
					ChainID:    req.res.ChainID,
					Contract:   req.res.Contract,
					LogID:      req.res.LogID.ToContractBytes32(),
					SealedSize: req.res.SealedSize,
					Calldata:   req.calldata,
					Ack: func(sub SubmitResult) {
						defer wg.Done()
						mu.Lock()
						results = append(results, sweepOutcome{group: g, key: key, res: FinalizeResult(req.res, sub)})
						mu.Unlock()
					},
				})
			}
		}

		// Submit phase: one batch per pass through the shared nonce authority.
		if len(ready) > 0 {
			r.pub.SubmitBatch(ctx, ready)
			ackDone := make(chan struct{})
			go func() { wg.Wait(); close(ackDone) }()
			select {
			case <-ctx.Done():
				return stats, ctx.Err()
			case <-ackDone:
			}
		}

		// Settle phase: classify finalized results; poison top seals fall back
		// to the next lower massif within this pass (W3).
		progressed := false
		for _, out := range results {
			switch out.res.Status {
			case StatusPublished:
				progressed = true
				r.recordAnchored(out.key, out.res, &stats)
			case StatusAlreadyAnchored:
				stats.Covered++
			case StatusReverted:
				stats.Unpublishable++
				r.logger.Error("unpublishable checkpoint skipped by resync sweep",
					"key", out.key, "reason", out.res.Reason, "chain", out.res.ChainID,
					"contract", out.res.Contract.Hex())
				if r.driveLowerMassifs(ctx, out.group, &stats) {
					progressed = true
				}
			default: // StatusRetry — tx never mined; retry next sweep.
				stats.Errors++
				r.logger.Warn("resync submit did not mine; retrying next sweep",
					"key", out.key, "reason", out.res.Reason)
			}
		}

		pending = blocked
		if !progressed {
			break
		}
		// Blocked groups retry from their top candidate next pass.
		for _, g := range pending {
			g.next = 0
		}
	}
	stats.Blocked = len(pending)
	return stats, nil
}

// assembled carries one ready candidate's read-phase output.
type assembled struct {
	key      string
	calldata []byte
	res      PublishResult
}

// assembleCandidate walks g's candidates from g.next until one is ready to
// submit (returned with done=false, outcome zero), the group is owner-gated
// (done=false, outcome StatusOwnerNotAnchored), or the group settles this
// sweep (done=true). Assemble-time terminal statuses fall through to lower
// massifs (W3), mirroring the submit-phase poison fallback.
func (r *Resync) assembleCandidate(ctx context.Context, g *logSeals, stats *SweepStats) (assembled, PublishStatus, bool) {
	for ; g.next < len(g.keys); g.next++ {
		key := g.keys[g.next]
		if ctx.Err() != nil {
			return assembled{}, 0, true
		}
		calldata, res, ready, err := r.pub.Assemble(ctx, key)
		if err != nil {
			stats.Errors++
			r.logger.Warn("resync assemble failed", "key", key, "error", err)
			return assembled{}, 0, true
		}
		if ready {
			return assembled{key: key, calldata: calldata, res: res}, 0, false
		}
		switch res.Status {
		case StatusOwnerNotAnchored:
			return assembled{}, StatusOwnerNotAnchored, false
		case StatusAlreadyAnchored:
			stats.Covered++
			return assembled{}, 0, true
		case StatusChainNotConfigured:
			stats.Errors++
			r.logger.Warn("resync skipped checkpoint", "key", key,
				"status", res.Status.String(), "reason", res.Reason)
			return assembled{}, 0, true
		default:
			// Terminal at assemble (poison-shaped): alert and try the next
			// lower massif of the same log.
			stats.Unpublishable++
			r.logger.Error("unpublishable checkpoint skipped by resync sweep",
				"key", key, "status", res.Status.String(), "reason", res.Reason)
		}
	}
	return assembled{}, 0, true // exhausted: every seal for this log is poison
}

// driveLowerMassifs synchronously drives g's remaining lower candidates after
// a submit-phase revert (W3): assemble + single-item batch + wait, until a
// candidate settles or the group is exhausted. Returns true when a candidate
// anchored.
func (r *Resync) driveLowerMassifs(ctx context.Context, g *logSeals, stats *SweepStats) bool {
	g.next++
	for {
		req, outcome, done := r.assembleCandidate(ctx, g, stats)
		if done {
			return false
		}
		if outcome == StatusOwnerNotAnchored {
			// Lower massif owner-gated after a poison top: extremely unusual;
			// leave for the next sweep rather than complicating the pass.
			return false
		}
		res := r.submitOne(ctx, req)
		switch res.Status {
		case StatusPublished:
			r.recordAnchored(req.key, res, stats)
			return true
		case StatusAlreadyAnchored:
			stats.Covered++
			return false
		case StatusReverted:
			stats.Unpublishable++
			r.logger.Error("unpublishable checkpoint skipped by resync sweep",
				"key", req.key, "reason", res.Reason, "chain", res.ChainID,
				"contract", res.Contract.Hex())
			g.next++
		default:
			stats.Errors++
			return false
		}
	}
}

// submitOne submits a single assembled candidate through SubmitBatch and
// waits for its finalized result (nonce stays with chainNonce, W1).
func (r *Resync) submitOne(ctx context.Context, req assembled) PublishResult {
	done := make(chan PublishResult, 1)
	r.pub.SubmitBatch(ctx, []AssembledPublish{{
		ChainID:    req.res.ChainID,
		Contract:   req.res.Contract,
		LogID:      req.res.LogID.ToContractBytes32(),
		SealedSize: req.res.SealedSize,
		Calldata:   req.calldata,
		Ack:        func(sub SubmitResult) { done <- FinalizeResult(req.res, sub) },
	}})
	select {
	case <-ctx.Done():
		return PublishResult{Key: req.key, Status: StatusRetry, Reason: ctx.Err().Error()}
	case res := <-done:
		return res
	}
}

// recordAnchored classifies a sweep-anchored checkpoint as an owner-gate
// handoff (the consumer deliberately acked it) or a genuine notification
// loss (W2/F7), and records the matching metric and log line.
func (r *Resync) recordAnchored(key string, res PublishResult, stats *SweepStats) {
	if r.handoffs.Recent(key, resyncHealthyWithin*r.interval) {
		stats.Handoffs++
		r.metrics.RecordResyncHandoff()
		r.logger.Info("owner-gated checkpoint anchored by resync sweep",
			"key", key, "sealedSize", res.SealedSize, "onchainSize", res.OnchainSize,
			"chain", res.ChainID, "contract", res.Contract.Hex(), "tx", res.TxHash.Hex())
		return
	}
	stats.Gaps++
	r.metrics.RecordResyncGap()
	r.logger.Warn("notification loss detected: checkpoint anchored by resync sweep",
		"key", key, "sealedSize", res.SealedSize, "onchainSize", res.OnchainSize,
		"chain", res.ChainID, "contract", res.Contract.Hex(), "tx", res.TxHash.Hex())
}

// listLogSeals pages the checkpoints prefix and returns one group per
// (height, log), keys ordered highest massif index first.
func (r *Resync) listLogSeals(ctx context.Context) ([]*logSeals, error) {
	type entry struct {
		key   string
		index uint32
	}
	byLog := make(map[string][]entry)

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
			byLog[group] = append(byLog[group], entry{key: obj.Key, index: ck.MassifIndex})
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		token = page.NextContinuationToken
	}

	groups := make([]*logSeals, 0, len(byLog))
	for _, entries := range byLog {
		sort.Slice(entries, func(i, j int) bool { return entries[i].index > entries[j].index })
		keys := make([]string, len(entries))
		for i, e := range entries {
			keys[i] = e.key
		}
		groups = append(groups, &logSeals{keys: keys})
	}
	return groups, nil
}
