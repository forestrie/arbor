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
	"net/http"
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

// resyncMaxSubmitsPerSweep bounds one sweep's transaction burst. The first
// lane rollout submitted ~90+ txs in one sweep; everything queued behind the
// burst exceeded ReceiptTimeout and churned as retries. Anything over budget
// simply waits for the next sweep.
const resyncMaxSubmitsPerSweep = 16

// resyncHorizon bounds how far back the sweep looks. Beyond it a sealed
// checkpoint is no longer a sweep candidate.
//
// The sweep exists to cover a LOST R2 NOTIFICATION (FOR-408): a notification is
// lost, or not, at the moment the object is written, and the sweep runs every
// interval — so a candidate that has been visible for hours has already been
// re-driven many times. Anything still unanchored by then is not waiting on a
// lost notification; it is waiting on a fix. Continuing to re-drive it forever
// made per-sweep work grow with TOTAL HISTORY rather than with outstanding
// work (709 objects listed to find 15 blocked), which is unbounded by
// construction for a backstop that is meant to be cheap.
//
// Stateless by design: the bound comes from the object's own LastModified,
// which the listing already returns, so nothing has to be remembered, written,
// or reconciled — and a restart cannot reset it.
//
// The cost is a real one and is why aged-out candidates that are still
// unanchored ALERT rather than disappearing: an infrastructure outage longer
// than the horizon would age out checkpoints that were never successfully
// driven, which is precisely the strand FOR-408 exists to prevent. Recovery is
// the operator re-drive ("poke") path the terminal-ack comment already
// anticipates.
//
// "Still unanchored" is a VERIFIED verdict, not an inference from age: an
// aged-out candidate is classified against on-chain state (one read-only
// Assemble, memoised per content in the settled cache) and only a candidate
// the chain does not cover alerts. Asserting it from age alone reported every
// checkpoint older than the horizon as stranded forever — ~1,750 ERRORs per
// sweep on lane A — which buried the real incidents the ERROR exists for.
const resyncHorizon = 12 * time.Hour

// resyncMaxAgedChecksPerSweep bounds how many aged-out candidates one sweep
// classifies with a read-only Assemble (7–10+ R2/RPC round trips each,
// including a massif read). The settled cache makes classification a
// once-per-content cost, but the cache is in-memory, so a restart re-learns
// every aged candidate: on lane A that is ~1,750 of them, which unbounded
// would turn the first sweep after a deploy into a ~15k-request burst that
// RPC rate limits answer with a wall of WARNs. Deferred candidates are past
// the horizon by definition — nothing is waiting on them this sweep — so
// spreading the warm-up over ~30 sweeps costs only a delay in re-surfacing a
// strand after a restart. Classification resumes each sweep at the log where
// the budget ran out (Resync.agedResume), so a deterministic prefix of
// uncacheable verdicts (Assemble errors, strands due for re-check) cannot
// starve the rest.
const resyncMaxAgedChecksPerSweep = 64

// strandRecheck is how long a verified strand verdict is trusted before it
// is re-verified against the chain. The re-check is what notices an operator
// re-drive (or a catch-up seal) having anchored it, and what keeps a strand's
// per-sweep cost at zero round trips in between so many strands cannot
// monopolise the check budget.
//
// A strand is logged at ERROR on TRANSITION — when first verified (once per
// process lifetime per content), when a re-check changes its verdict, and
// (at INFO) when it is found anchored — not on every sweep. The first
// rollout of verified classification showed lane A carrying ~1,000 genuine
// never-anchored test forests: repeating each at ERROR every 120s was the
// same wall of noise the false alarms had been, only truthful. The standing
// signal is the sweep summary's "stranded" count and the
// publisher_resync_stranded gauge, which is what an alert rule should use.
const strandRecheck = 30 * time.Minute

// verdictCap bounds the settled and strand caches; beyond it the oldest
// entries are pruned (re-classifying an evicted entry costs one Assemble).
const verdictCap = 16384

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
	// RecordResyncStranded sets the number of aged-out checkpoints the last
	// sweep verified as still unanchored (the FOR-408 strand shape; each one
	// needs an operator re-drive). A gauge, not a counter: the same strand is
	// re-verified every sweep until it is anchored or re-sealed.
	RecordResyncStranded(n int)
}

type noopResyncMetrics struct{}

func (noopResyncMetrics) RecordResyncGap()         {}
func (noopResyncMetrics) RecordResyncHandoff()     {}
func (noopResyncMetrics) RecordResyncSweep(string) {}
func (noopResyncMetrics) RecordResyncStranded(int) {}

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
	// Unpublishable counts seals newly proven unpublishable this sweep (a
	// mined revert or assemble-terminal status); lower massifs of the same
	// log are attempted in their place (W3).
	Unpublishable int
	// AgedOut counts candidates older than resyncHorizon. None is driven;
	// each is classified (or deferred) rather than assumed stranded, and
	// lands in exactly one of Covered, Stranded, AgedDeferred or Errors.
	AgedOut int
	// AgedChecked counts aged-out candidates classified this sweep with a
	// read-only Assemble (bounded by resyncMaxAgedChecksPerSweep; a settled
	// cache hit or a calldata-invalid poison hit costs no check).
	AgedChecked int
	// AgedDeferred counts aged-out candidates left unclassified this sweep
	// because the check budget was spent; they are picked up next sweep.
	AgedDeferred int
	// Stranded counts aged-out candidates VERIFIED still unanchored. Each is
	// logged at ERROR once per sweep: a seal that aged out while unanchored
	// is the FOR-408 strand shape and needs an operator re-drive.
	Stranded int
	// PoisonSkipped counts candidates skipped via the poison cache — seals
	// already proven unpublishable at their current ETag. No gas, no ERROR.
	PoisonSkipped int
	// CapDeferred counts logs left for the next sweep because the per-sweep
	// submission budget was exhausted (bounds burst-induced receipt
	// timeouts on the shared EOA).
	CapDeferred int
	// Errors counts keys abandoned this sweep on infrastructure errors.
	Errors int
}

// parseListedTime decodes the listing's LastModified. An unparseable value
// yields the zero time, which agedOut treats as in-window: a backend that
// formats timestamps unexpectedly must not cause candidates to be dropped
// silently.
func parseListedTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, http.TimeFormat} {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

// sealRef is one sealed checkpoint object: its key and the listed ETag (the
// content identity the poison skip-cache is keyed on).
type sealRef struct {
	key  string
	etag string
	// lastModified is the object's own write time, straight from the listing.
	// It is what makes the horizon stateless — see resyncHorizon. Zero when the
	// backend returned an unparseable timestamp, which is treated as "in
	// window" so a formatting quirk can never silently drop a candidate.
	lastModified time.Time
}

// agedOut reports whether this seal is past the sweep horizon.
func (s sealRef) agedOut(now time.Time) bool {
	if s.lastModified.IsZero() {
		return false
	}
	return now.Sub(s.lastModified) > resyncHorizon
}

// logSeals is one log's sealed checkpoints, highest massif index first.
// The sweep drives the highest publishable seal; on a poison (reverted) top
// seal it falls back to the next lower massif (plan-2607-08 W3) so a
// publishable prefix is never starved.
type logSeals struct {
	seals []sealRef
	next  int // index into seals of the candidate to drive
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

	// poison maps checkpoint key -> the seal content (ETag) proven
	// unpublishable (mined revert or assemble-terminal), with ageing: an
	// entry is re-adjudicated on an exponential backoff (1h doubling, 24h
	// cap) so a transiently-misassembled seal is not cemented forever
	// (FOR-411), while genuine poison re-mines at most ~1/day. A content
	// change (new ETag — e.g. a FOR-410 self-heal re-seal) clears the entry
	// immediately. In-memory only: a restart re-mines each at most once.
	poison map[string]*poisonEntry

	// settled maps checkpoint key -> the seal content (ETag) verified anchored
	// on-chain, so an aged-out candidate is classified once per content rather
	// than once per sweep (which would make sweep cost track total history
	// again — the exact regression resyncHorizon exists to prevent). Anchoring
	// is monotonic, so the verdict never goes stale for the same bytes; a
	// re-seal arrives as a new ETag and misses. In-memory only, like poison.
	settled map[string]*settledEntry

	// strands maps checkpoint key -> the seal content verified still
	// unanchored past the horizon, with what the chain said. Counted from
	// cache every sweep, re-verified on strandRecheck, logged on transition.
	strands map[string]*strandEntry

	// agedResume is the sorted-group index at which the previous sweep's
	// aged-check budget ran out; this sweep's walk starts there, so warm-up
	// proceeds through the listing instead of re-spending the budget on the
	// same deterministic prefix.
	agedResume int
}

// settledEntry records one seal content verified anchored, and when.
type settledEntry struct {
	etag string
	at   time.Time
}

// strandEntry records one seal content verified unanchored past the horizon.
type strandEntry struct {
	etag   string
	at     time.Time // last verification
	since  time.Time // first verification of this verdict
	status string    // "publishable", or the not-ready PublishStatus name
	reason string
	// sized is set when the verdict came from a full assemble that read the
	// sizes; the owner-gated path returns before it does.
	sized           bool
	sealed, onchain uint64
}

// poisonEntry records one unpublishable seal content and its retry state.
type poisonEntry struct {
	etag   string
	at     time.Time
	tries  int
	reason string // decoded revert name or assemble-terminal reason
	// calldataInvalid marks a revert that can never be resolved by
	// re-submitting the same bytes (RevertIsCalldataInvalid). Such an entry is
	// not re-adjudicated on backoff at all — only a re-seal, which arrives as
	// a changed ETag, clears it. Ageing it would burn gas re-proving a fact
	// the contract already settled.
	calldataInvalid bool
}

const (
	poisonRetryBase = time.Hour
	poisonRetryMax  = 24 * time.Hour
)

// poisonBackoff is the wait before re-adjudicating a poison entry.
func poisonBackoff(tries int) time.Duration {
	d := poisonRetryBase
	for i := 0; i < tries && d < poisonRetryMax; i++ {
		d *= 2
	}
	if d > poisonRetryMax {
		return poisonRetryMax
	}
	return d
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
		poison:   make(map[string]*poisonEntry),
		settled:  make(map[string]*settledEntry),
		strands:  make(map[string]*strandEntry),
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
			r.metrics.RecordResyncStranded(stats.Stranded)
			if stats.Gaps > 0 || stats.Blocked > 0 || stats.Errors > 0 || stats.Unpublishable > 0 || stats.CapDeferred > 0 || stats.Stranded > 0 {
				r.logger.Warn("resync sweep",
					"listed", stats.Listed, "gaps", stats.Gaps, "handoffs", stats.Handoffs,
					"covered", stats.Covered, "blocked", stats.Blocked,
					"unpublishable", stats.Unpublishable, "poisonSkipped", stats.PoisonSkipped,
					"stranded", stats.Stranded, "agedOut", stats.AgedOut,
					"agedChecked", stats.AgedChecked, "agedDeferred", stats.AgedDeferred,
					"capDeferred", stats.CapDeferred, "errors", stats.Errors)
			} else {
				r.logger.Info("resync sweep clean", "listed", stats.Listed,
					"handoffs", stats.Handoffs, "poisonSkipped", stats.PoisonSkipped,
					"agedOut", stats.AgedOut, "agedChecked", stats.AgedChecked,
					"agedDeferred", stats.AgedDeferred)
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

	// Start the walk where the last sweep's aged-check budget ran out; the
	// owner-ordering passes below are a fixpoint, so order is not
	// correctness, only fairness of the budget.
	offset := 0
	if n := len(groups); n > 0 {
		offset = r.agedResume % n
		groups = append(append(make([]*logSeals, 0, n), groups[offset:]...), groups[:offset]...)
	}
	firstDeferred := -1

	budget := resyncMaxSubmitsPerSweep
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
		for i, g := range pending {
			deferredBefore := stats.AgedDeferred
			req, outcome, done := r.assembleCandidate(ctx, g, &stats)
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			if pass == 0 && firstDeferred < 0 && stats.AgedDeferred > deferredBefore {
				firstDeferred = (offset + i) % len(groups)
			}
			switch {
			case done:
				// settled at assemble time (covered / errors / exhausted)
			case outcome == StatusOwnerNotAnchored:
				blocked = append(blocked, g)
			case budget <= 0:
				// Ready but over budget: classification still happened above
				// (covered/poison progress is free); only the submission
				// waits for the next sweep.
				stats.CapDeferred++
			default:
				budget--
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
				r.markSettled(out.group, out.key)
				r.recordAnchored(out.key, out.res, &stats)
			case StatusAlreadyAnchored:
				stats.Covered++
				r.markSettled(out.group, out.key)
			case StatusReverted:
				stats.Unpublishable++
				r.markPoison(out.group, out.key, out.res.Reason)
				r.logger.Error("unpublishable checkpoint skipped by resync sweep",
					"key", out.key, "reason", out.res.Reason, "chain", out.res.ChainID,
					"contract", out.res.Contract.Hex(),
					"calldataInvalid", RevertIsCalldataInvalid(out.res.Reason))
				if r.driveLowerMassifs(ctx, out.group, &stats, &budget) {
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
	if firstDeferred >= 0 {
		r.agedResume = firstDeferred
	} else {
		r.agedResume = 0
	}
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
//
// Age changes what a verdict MEANS, not how it is reached. Every seal walks
// the same ladder — settled cache, poison cache, Assemble — but one past
// resyncHorizon is never submitted or left blocked: a verdict the chain does
// not cover is a strand (alerted once per sweep per log, cached, re-verified
// on strandRecheck), an unverified one is deferred (the read-only check
// budget), and only "already anchored" is the quiet, healthy shape. A strand
// is exactly the FOR-408 strand this sweep exists to prevent, so it must be
// visible and operator-actionable rather than silently dropped; recovery is
// the operator re-drive ("poke") path, and the sealed vs on-chain sizes in
// the line say how far behind the log is.
func (r *Resync) assembleCandidate(ctx context.Context, g *logSeals, stats *SweepStats) (assembled, PublishStatus, bool) {
	now := time.Now()
	strandLogged := false
	for ; g.next < len(g.seals); g.next++ {
		ref := g.seals[g.next]
		key := ref.key
		if ctx.Err() != nil {
			return assembled{}, 0, true
		}
		aged := ref.agedOut(now)
		if aged && strandLogged {
			// One alert per log: lower aged seals of a stranded log add
			// nothing an operator can act on. In-window seals below are
			// still driven (an out-of-band rewrite can put one there).
			continue
		}
		if aged {
			stats.AgedOut++
		}
		// Settled cache: anchored at exactly this content. Anchoring is
		// monotonic, so the verdict is final for these bytes whether the
		// seal is in-window or aged — no Assemble until a re-seal.
		if r.isSettled(key, ref.etag) {
			stats.Covered++
			return assembled{}, 0, true
		}
		// Poison cache: a seal proven unpublishable at this exact content is
		// skipped without assembling or (worse) re-mining its revert. A
		// changed ETag (re-seal) or an elapsed backoff (FOR-411 ageing)
		// clears it for one fresh adjudication.
		//
		// A calldata-invalid revert never ages back in: the same bytes cannot
		// become valid, so only a re-seal (new ETag) can clear it.
		if e, known := r.poison[key]; known && e.etag == ref.etag &&
			(e.calldataInvalid || time.Since(e.at) < poisonBackoff(e.tries)) {
			if aged {
				// Known unpublishable and past the horizon: a strand whose
				// reason the chain already gave. Free — no round trips.
				r.cacheStrand(ref, stats, &strandEntry{status: StatusReverted.String(), reason: e.reason})
				strandLogged = true
				continue
			}
			stats.PoisonSkipped++
			continue
		}
		if aged {
			if e, ok := r.strands[key]; ok && e.etag == ref.etag && now.Sub(e.at) < strandRecheck {
				stats.Stranded++ // standing verdict: counted, not re-logged
				strandLogged = true
				continue
			}
			if stats.AgedChecked >= resyncMaxAgedChecksPerSweep {
				// Unverified: nothing below may settle this log on its
				// behalf (a cached lower verdict would hide a strand here).
				stats.AgedDeferred++
				return assembled{}, 0, true
			}
			stats.AgedChecked++
		}
		calldata, res, ready, err := r.pub.Assemble(ctx, key)
		if err != nil {
			stats.Errors++
			r.logger.Warn("resync assemble failed", "key", key, "error", err)
			return assembled{}, 0, true
		}
		if ready {
			if aged {
				// The plainest strand: the calldata builds, the chain is
				// behind the seal, and nothing will submit it.
				r.cacheStrand(ref, stats, &strandEntry{status: "publishable", reason: res.Reason,
					sized: true, sealed: res.SealedSize, onchain: res.OnchainSize})
				strandLogged = true
				continue
			}
			return assembled{key: key, calldata: calldata, res: res}, 0, false
		}
		switch res.Status {
		case StatusOwnerNotAnchored:
			if aged {
				// The 2026-07-19 shape: the owner never anchored (or the
				// forest never resolved), so nothing under it can.
				r.cacheStrand(ref, stats, &strandEntry{status: res.Status.String(), reason: res.Reason})
				strandLogged = true
				continue
			}
			return assembled{}, StatusOwnerNotAnchored, false
		case StatusAlreadyAnchored:
			stats.Covered++
			r.cacheSettled(key, ref.etag)
			if e, ok := r.strands[key]; ok && e.etag == ref.etag {
				// The transition an operator is waiting for.
				delete(r.strands, key)
				r.logger.Info("stranded checkpoint now anchored", "key", key,
					"strandedSince", e.since.UTC().Format(time.RFC3339))
			}
			return assembled{}, 0, true
		case StatusChainNotConfigured:
			// Unverifiable, not unanchored (D3): this publisher cannot read
			// the forest's chain. Never a strand — that is a verified verdict.
			stats.Errors++
			r.logger.Warn("resync skipped checkpoint", "key", key,
				"status", res.Status.String(), "reason", res.Reason)
			return assembled{}, 0, true
		default:
			// Terminal at assemble (poison-shaped): alert once, cache, and try
			// the next lower massif of the same log.
			stats.Unpublishable++
			r.cachePoison(key, ref.etag, res.Reason)
			r.logger.Error("unpublishable checkpoint skipped by resync sweep",
				"key", key, "status", res.Status.String(), "reason", res.Reason,
				"calldataInvalid", RevertIsCalldataInvalid(res.Reason))
		}
	}
	return assembled{}, 0, true // exhausted: every seal for this log is poison
}

// sameVerdict reports whether two strand entries say the same thing about
// the same content, so a re-check that confirms it is not re-logged.
func (e *strandEntry) sameVerdict(o *strandEntry) bool {
	return e.etag == o.etag && e.status == o.status && e.reason == o.reason &&
		e.sized == o.sized && e.sealed == o.sealed && e.onchain == o.onchain
}

// cacheStrand records a verified strand verdict, counts it, and logs it at
// ERROR only when it is new for this content or differs from the cached one
// (see strandRecheck for why not every sweep).
func (r *Resync) cacheStrand(ref sealRef, stats *SweepStats, e *strandEntry) {
	stats.Stranded++
	now := time.Now()
	e.etag, e.at, e.since = ref.etag, now, now
	prev, had := r.strands[ref.key]
	if had && prev.sameVerdict(e) {
		prev.at = now
		return
	}
	if had {
		e.since = prev.since
	} else if len(r.strands) >= verdictCap {
		evictOldest(r.strands, func(e *strandEntry) time.Time { return e.at })
	}
	r.strands[ref.key] = e
	args := []any{
		"key", ref.key, "lastModified", ref.lastModified.UTC().Format(time.RFC3339),
		"horizon", resyncHorizon.String(), "status", e.status, "reason", e.reason,
	}
	if e.sized {
		args = append(args, "sealedSize", e.sealed, "onchainSize", e.onchain)
	}
	r.logger.Error("checkpoint aged out of resync horizon, still unanchored", args...)
}

// isSettled reports whether key was verified anchored at exactly this ETag.
func (r *Resync) isSettled(key, etag string) bool {
	e, ok := r.settled[key]
	return ok && e.etag == etag
}

// cacheSettled records that key's content at etag is anchored on-chain.
func (r *Resync) cacheSettled(key, etag string) {
	if e, ok := r.settled[key]; ok {
		e.etag, e.at = etag, time.Now()
		return
	}
	if len(r.settled) >= verdictCap {
		evictOldest(r.settled, func(e *settledEntry) time.Time { return e.at })
	}
	r.settled[key] = &settledEntry{etag: etag, at: time.Now()}
}

// evictOldest drops the entry with the earliest timestamp from a verdict cache.
func evictOldest[T any](m map[string]*T, at func(*T) time.Time) {
	oldestKey, oldest := "", time.Time{}
	for k, e := range m {
		if t := at(e); oldest.IsZero() || t.Before(oldest) {
			oldestKey, oldest = k, t
		}
	}
	delete(m, oldestKey)
}

// markSettled caches a submit-phase anchored verdict for g's candidate key at
// its listed ETag (the submit path carries the key, not the ref).
func (r *Resync) markSettled(g *logSeals, key string) {
	for _, ref := range g.seals {
		if ref.key == key {
			r.cacheSettled(key, ref.etag)
			return
		}
	}
}

// markPoison caches out-of-band (submit-phase) poison for g's current
// candidate key at its listed ETag.
func (r *Resync) markPoison(g *logSeals, key, reason string) {
	for _, ref := range g.seals {
		if ref.key == key {
			r.cachePoison(key, ref.etag, reason)
			return
		}
	}
}

// cachePoison records (or re-arms with backoff) a poison entry.
func (r *Resync) cachePoison(key, etag, reason string) {
	invalid := RevertIsCalldataInvalid(reason)
	if e, ok := r.poison[key]; ok && e.etag == etag {
		e.tries++
		e.at = time.Now()
		// Latch: once these bytes are known invalid, a later adjudication that
		// reported a vaguer reason must not re-arm the backoff.
		e.calldataInvalid = e.calldataInvalid || invalid
		if reason != "" {
			e.reason = reason
		}
		return
	}
	r.poison[key] = &poisonEntry{etag: etag, at: time.Now(), calldataInvalid: invalid, reason: reason}
}

// driveLowerMassifs synchronously drives g's remaining lower candidates after
// a submit-phase revert (W3): assemble + single-item batch + wait, until a
// candidate settles or the group is exhausted. Returns true when a candidate
// anchored.
func (r *Resync) driveLowerMassifs(ctx context.Context, g *logSeals, stats *SweepStats, budget *int) bool {
	g.next++
	for {
		if *budget <= 0 {
			stats.CapDeferred++
			return false
		}
		req, outcome, done := r.assembleCandidate(ctx, g, stats)
		if done {
			return false
		}
		if outcome == StatusOwnerNotAnchored {
			// Lower massif owner-gated after a poison top: extremely unusual;
			// leave for the next sweep rather than complicating the pass.
			return false
		}
		*budget--
		res := r.submitOne(ctx, req)
		switch res.Status {
		case StatusPublished:
			r.markSettled(g, req.key)
			r.recordAnchored(req.key, res, stats)
			return true
		case StatusAlreadyAnchored:
			stats.Covered++
			r.markSettled(g, req.key)
			return false
		case StatusReverted:
			stats.Unpublishable++
			r.markPoison(g, req.key, res.Reason)
			r.logger.Error("unpublishable checkpoint skipped by resync sweep",
				"key", req.key, "reason", res.Reason, "chain", res.ChainID,
				"contract", res.Contract.Hex(),
				"calldataInvalid", RevertIsCalldataInvalid(res.Reason))
			g.next++
		default:
			stats.Errors++
			r.logger.Warn("resync submit did not mine; retrying next sweep",
				"key", req.key, "reason", res.Reason)
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
		key          string
		etag         string
		index        uint32
		lastModified time.Time
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
			byLog[group] = append(byLog[group], entry{
				key:          obj.Key,
				etag:         obj.ETag,
				index:        ck.MassifIndex,
				lastModified: parseListedTime(obj.LastModified),
			})
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		token = page.NextContinuationToken
	}

	groups := make([]*logSeals, 0, len(byLog))
	for _, entries := range byLog {
		sort.Slice(entries, func(i, j int) bool { return entries[i].index > entries[j].index })
		seals := make([]sealRef, len(entries))
		for i, e := range entries {
			seals[i] = sealRef{key: e.key, etag: e.etag, lastModified: e.lastModified}
		}
		groups = append(groups, &logSeals{seals: seals})
	}
	// Deterministic order (map iteration is randomized): monotonic poison
	// burn-down and gap pickup across sweeps rather than random subsets.
	sort.Slice(groups, func(i, j int) bool { return groups[i].seals[0].key < groups[j].seals[0].key })
	return groups, nil
}
