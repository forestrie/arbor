// Package consumer is the publisher's Cloudflare Queue pull consumer. It polls
// the checkpoints-prefix queue, turns each R2 PutObject notification into a
// one-shot publish, and acks only the messages whose outcome is terminal
// (published / already-anchored / deterministic revert). Transient outcomes
// (unconfigured chain, infra error) are left unacked so the visibility
// timeout redelivers them. owner_not_anchored depends on the resync sweep
// (plan-2607-07): with RESYNC_INTERVAL set the message is acked after the
// in-cycle drain and the sweep re-drives it once the owner anchors — queue
// redelivery would only march it to the retry cliff (dead-lettered children
// cannot be revived by a late owner, FOR-408 §2.3). With the sweep disabled,
// the pre-sweep behaviour stands: leave unacked and rely on redelivery.
package consumer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/forestrie/arbor/services/pkgs/logredact"
	"github.com/forestrie/arbor/services/publisher"
	"github.com/forestrie/arbor/services/publisher/metrics"
)

// publishCore is the subset of *publisher.Publisher the consumer drives. It is
// an interface so the drain (assemble → submit) can be tested with a fake that
// flips owner_not_anchored to ready after N polls. *publisher.Publisher
// satisfies it.
type publishCore interface {
	From() common.Address
	Assemble(ctx context.Context, key string) (calldata []byte, res publisher.PublishResult, ready bool, err error)
	SubmitBatch(ctx context.Context, reqs []publisher.AssembledPublish)
}

// QueueConsumer coordinates Cloudflare Queue message consumption for the publisher.
type QueueConsumer struct {
	cfg        publisher.Config
	httpClient *publisher.HTTPClient
	logger     *slog.Logger
	pub        publishCore
	metrics    *metrics.Metrics

	// resyncHealthy and handoffs are set via WithResync when the resync
	// sweep is enabled (plan-2607-08 W2): owner-gated acks require a
	// recently-successful sweep, and every such ack is recorded so the
	// sweep can tell a deliberate handoff from a lost notification.
	resyncHealthy func() bool
	handoffs      *publisher.OwnerGateHandoffs
}

// NewQueueConsumer constructs a QueueConsumer.
func NewQueueConsumer(
	cfg publisher.Config, httpClient *publisher.HTTPClient, logger *slog.Logger,
	pub *publisher.Publisher, m *metrics.Metrics,
) *QueueConsumer {
	return &QueueConsumer{cfg: cfg, httpClient: httpClient, logger: logger, pub: pub, metrics: m}
}

const defaultBackoffBase = 10 * time.Millisecond

// ConsumeQueue runs the poll/process loop until ctx is cancelled.
func (q *QueueConsumer) ConsumeQueue(ctx context.Context) {
	backoffBase := q.cfg.PollIntervalMin
	if backoffBase == 0 {
		backoffBase = q.cfg.BackoffBase
	}
	if backoffBase == 0 {
		backoffBase = q.cfg.PollIntervalMax / 8
	}
	if backoffBase == 0 {
		backoffBase = defaultBackoffBase
	}
	jitterFrac := q.cfg.PollJitter
	if jitterFrac <= 0 {
		jitterFrac = 0.1
	}

	q.logger.Info("starting publisher queue consumer",
		"queueURL_sha256", logredact.StringSHA256Hex(q.cfg.QueueURL),
		"pollIntervalMin", q.cfg.PollIntervalMin,
		"pollIntervalMax", q.cfg.PollIntervalMax,
		"batchSize", q.cfg.QueueBatchSize,
		"publisherEOA", q.pub.From().Hex(),
	)

	currentBackoff := q.cfg.PollIntervalMin
	for {
		select {
		case <-ctx.Done():
			q.logger.Debug("queue consumer stopping")
			return
		default:
		}

		msgCount, err := q.PullAndProcessMessages(ctx)
		if err != nil {
			q.logger.Error("failed to pull/process messages", "error", err)
			q.metrics.RecordPoll("failure")
		} else {
			switch {
			case msgCount == 0:
				q.metrics.RecordPoll("empty")
			case msgCount >= q.cfg.QueueBatchSize:
				q.metrics.RecordPoll("full")
			default:
				q.metrics.RecordPoll("partial")
			}
		}

		var sleep time.Duration
		switch {
		case msgCount >= q.cfg.QueueBatchSize:
			sleep = q.cfg.PollIntervalMin
			currentBackoff = q.cfg.PollIntervalMin
		case msgCount > 0:
			if currentBackoff == 0 {
				currentBackoff = backoffBase
			}
			sleep = currentBackoff
		default:
			if currentBackoff == 0 {
				currentBackoff = backoffBase
			} else {
				currentBackoff *= 2
			}
			if currentBackoff > q.cfg.PollIntervalMax {
				currentBackoff = q.cfg.PollIntervalMax
			}
			sleep = currentBackoff
		}
		if sleep > 0 && jitterFrac > 0 {
			// ± jitterFrac of the sleep, centred on zero.
			span := int64(float64(sleep) * jitterFrac * 2)
			if span > 0 {
				jitter := time.Duration(rand.Int63n(span)) - time.Duration(float64(sleep)*jitterFrac)
				sleep += jitter
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		}
	}
}

// PullAndProcessMessages pulls one batch and processes it, returning the count.
func (q *QueueConsumer) PullAndProcessMessages(ctx context.Context) (int, error) {
	start := time.Now()
	base, err := cloudflareQueueAPIBase(q.cfg.QueueURL)
	if err != nil {
		return 0, fmt.Errorf("QUEUE_URL: %w", err)
	}
	pullURL := base + "/messages/pull"

	payload := struct {
		BatchSize           int `json:"batch_size"`
		VisibilityTimeoutMs int `json:"visibility_timeout_ms,omitempty"`
	}{q.cfg.QueueBatchSize, int(q.cfg.VisibilityTimeout.Milliseconds())}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, pullURL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("create pull request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+q.cfg.QueueToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := q.httpClient.Do(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("pull messages: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		q.logger.Warn("queue pull failed", "status", resp.StatusCode, "body_sha256", logredact.SHA256Hex(b))
		return 0, fmt.Errorf("pull failed: status=%d", resp.StatusCode)
	}

	var pr QueuePullResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return 0, fmt.Errorf("decode pull response: %w", err)
	}
	n := len(pr.Result.Messages)
	q.metrics.ObservePollDuration(time.Since(start).Seconds())
	q.metrics.ObserveMessagesPerPoll(n)
	q.logger.Info("pulled messages", "count", n, "backlog", pr.Result.MessageBacklogCount)

	q.processBatch(ctx, pr.Result.Messages)
	return n, nil
}

// logGroup coalesces a batch's messages for one log: the highest massifIndex is
// the primary (published), the lower massifs are subsumed siblings (acked when
// the primary anchors — the latest seal covers them via the consistency chain).
type logGroup struct {
	primary  QueueMessage
	key      string
	massif   uint32
	siblings []QueueMessage
}

// processBatch coalesces messages by log (highest massif per log), assembles the
// primaries concurrently (reads only), handles early-exit outcomes, then hands
// the ready ones to the batched submitter. Receipts confirm asynchronously; each
// primary's ack (and its subsumed siblings') fires when its receipt resolves.
func (q *QueueConsumer) processBatch(ctx context.Context, msgs []QueueMessage) {
	if len(msgs) == 0 {
		return
	}
	q.metrics.AddMessagesProcessed(len(msgs))

	groups := q.coalesce(ctx, msgs)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		ready    []publisher.AssembledPublish
		deferred []deferredGroup
	)
	for _, g := range groups {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, st, res := q.assembleGroup(ctx, g)
			mu.Lock()
			switch st {
			case assembleReady:
				ready = append(ready, req)
			case assembleDeferred:
				deferred = append(deferred, deferredGroup{g: g, res: res})
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(ready) > 0 {
		// Returns once sends are admitted; acks fire async from the collector.
		q.pub.SubmitBatch(ctx, ready)
	}

	// Drain owner_not_anchored groups: their owner (authority log) may have just
	// been submitted by this cycle — or a prior one — and anchors within a few
	// seconds. Re-assemble against fresh on-chain logState until they clear or
	// OwnerWait elapses, rather than releasing straight to a full
	// visibility-timeout redelivery (FOR-395, plan-2607-06).
	q.drainDeferred(ctx, deferred)
}

// coalesce groups the batch by logId, keeping the highest massifIndex per log as
// the primary and the rest as subsumed siblings. Non-checkpoint messages are
// acked immediately (poison avoidance).
func (q *QueueConsumer) coalesce(ctx context.Context, msgs []QueueMessage) []logGroup {
	byLog := make(map[string]*logGroup)
	for _, msg := range msgs {
		key, ok := q.checkpointKeyFromMessage(msg)
		if !ok {
			q.ackMsg(ctx, msg)
			continue
		}
		ck, err := publisher.ParseCheckpointKey(key) // already validated by checkpointKeyFromMessage
		if err != nil {
			q.ackMsg(ctx, msg)
			continue
		}
		id := ck.LogID.String()
		g, exists := byLog[id]
		if !exists {
			byLog[id] = &logGroup{primary: msg, key: key, massif: ck.MassifIndex}
			continue
		}
		if ck.MassifIndex > g.massif {
			g.siblings = append(g.siblings, g.primary)
			g.primary, g.key, g.massif = msg, key, ck.MassifIndex
		} else {
			g.siblings = append(g.siblings, msg)
		}
	}
	out := make([]logGroup, 0, len(byLog))
	for _, g := range byLog {
		out = append(out, *g)
	}
	return out
}

// assembleState routes a group after its read phase.
type assembleState int

const (
	// assembleDone: no further action this cycle — either settled here
	// (acked/released terminal outcome) or left unacked on an infra error to
	// redeliver.
	assembleDone assembleState = iota
	// assembleReady: calldata is set; submit it.
	assembleReady
	// assembleDeferred: owner_not_anchored — hold for the drain, do NOT settle.
	assembleDeferred
)

// deferredGroup is an owner_not_anchored group held by the drain, carrying the
// last PublishResult so it can be released with the correct status on timeout.
type deferredGroup struct {
	g   logGroup
	res publisher.PublishResult
}

// assembleGroup runs the read phase for a log's primary. A ready group returns
// an AssembledPublish whose Ack finalises the primary and its subsumed siblings
// when the receipt resolves. An owner_not_anchored group is returned deferred
// (NOT settled) so the drain can re-assemble it; every other non-ready outcome
// is settled here, as before.
func (q *QueueConsumer) assembleGroup(ctx context.Context, g logGroup) (publisher.AssembledPublish, assembleState, publisher.PublishResult) {
	start := time.Now()
	calldata, res, ready, err := q.pub.Assemble(ctx, g.key)
	if err != nil {
		q.metrics.ObservePublishDuration(time.Since(start).Seconds())
		q.logger.Warn("assemble failed", "messageID", g.primary.ID, "key", g.key, "error", err)
		return publisher.AssembledPublish{}, assembleDone, res // leave primary + siblings unacked
	}
	if !ready {
		if res.Status == publisher.StatusOwnerNotAnchored {
			// Hold for the drain; do not settle. The drain re-assembles it to
			// ready once the owner anchors, or releases it on timeout.
			return publisher.AssembledPublish{}, assembleDeferred, res
		}
		q.metrics.ObservePublishDuration(time.Since(start).Seconds())
		q.finishGroup(ctx, g, res)
		return publisher.AssembledPublish{}, assembleDone, res
	}
	return publisher.AssembledPublish{
		ChainID:    res.ChainID,
		Contract:   res.Contract,
		LogID:      res.LogID.ToContractBytes32(),
		SealedSize: res.SealedSize,
		Calldata:   calldata,
		Ack: func(sub publisher.SubmitResult) {
			q.metrics.ObservePublishDuration(time.Since(start).Seconds())
			q.finishGroup(ctx, g, publisher.FinalizeResult(res, sub))
		},
	}, assembleReady, res
}

// drainDeferred re-assembles owner_not_anchored groups against fresh on-chain
// logState until they clear or OwnerWait elapses, submitting any that become
// ready. Stragglers are released (finishGroup with owner_not_anchored) for
// redelivery — the pre-FOR-395 slow path. OwnerWait == 0 disables the drain
// (release immediately). The drain reads chain state directly, so it needs no
// coupling to the async receipt collector: an owner submitted by this cycle (or
// a prior one) becomes visible in logState once it mines (plan-2607-06 C5).
func (q *QueueConsumer) drainDeferred(ctx context.Context, deferred []deferredGroup) {
	if len(deferred) == 0 {
		return
	}
	if q.cfg.OwnerWait <= 0 {
		q.releaseDeferred(ctx, deferred)
		return
	}
	poll := q.cfg.OwnerPoll
	if poll <= 0 {
		poll = 2 * time.Second
	}
	deadline := time.Now().Add(q.cfg.OwnerWait)

	for len(deferred) > 0 {
		// Cap the sleep to the remaining budget so a poll interval longer than
		// OwnerWait (or than the time left) can never hold the message past
		// OwnerWait — holding it past its lease would let the queue redeliver it
		// while we still have it in flight, duplicating the publish (the same
		// hazard as VISIBILITY_TIMEOUT > RECEIPT_TIMEOUT).
		wait := poll
		if rem := time.Until(deadline); rem < wait {
			wait = rem
		}
		if wait <= 0 {
			q.releaseDeferred(ctx, deferred)
			return
		}
		select {
		case <-ctx.Done():
			q.releaseDeferred(ctx, deferred)
			return
		case <-time.After(wait):
		}

		var (
			ready []publisher.AssembledPublish
			still []deferredGroup
		)
		for _, dg := range deferred {
			req, st, res := q.assembleGroup(ctx, dg.g)
			switch st {
			case assembleReady:
				ready = append(ready, req)
			case assembleDeferred:
				still = append(still, deferredGroup{g: dg.g, res: res})
				// assembleDone: settled inside assembleGroup (now already-anchored,
				// or a revert) — nothing more to do.
			}
		}
		if len(ready) > 0 {
			q.pub.SubmitBatch(ctx, ready)
		}
		deferred = still
		if len(deferred) == 0 {
			return
		}
		if !time.Now().Before(deadline) {
			q.releaseDeferred(ctx, deferred)
			return
		}
	}
}

// releaseDeferred hands each still-blocked group back for redelivery, recording
// the owner_not_anchored outcome. finishGroup does not ack that status, so the
// message redelivers on lease expiry — identical to the pre-drain behaviour.
func (q *QueueConsumer) releaseDeferred(ctx context.Context, deferred []deferredGroup) {
	for _, dg := range deferred {
		q.finishGroup(ctx, dg.g, dg.res)
	}
}

// finishGroup settles a log's primary and, only when the primary actually
// anchored (published / already-anchored), acks its subsumed siblings too — the
// anchored highest seal covers their lower massifs via the consistency chain. On
// an unpublishable primary (StatusReverted) the primary is terminally acked but
// the siblings are NOT: a lower massif is not necessarily unpublishable, so it is
// left to redeliver and be adjudicated on its own. On retry, siblings also
// redeliver with the primary.
func (q *QueueConsumer) finishGroup(ctx context.Context, g logGroup, res publisher.PublishResult) {
	q.finish(ctx, g.primary, g.key, res)
	anchored := res.Status == publisher.StatusPublished || res.Status == publisher.StatusAlreadyAnchored
	// Under the resync sweep, an owner-gated primary is acked (see finish);
	// its subsumed lower-massif siblings follow it — the sweep re-drives from
	// R2 + chain state, not from the queue.
	if anchored || q.resyncAcksOwnerGated(res.Status) {
		for _, sib := range g.siblings {
			q.ackMsg(ctx, sib)
		}
	}
}

// WithResync arms the owner-gated ack contract: healthy gates each ack on a
// recently-successful sweep, and handoffs records what was acked so the
// sweep's "notification loss" signal stays honest (plan-2607-08 W2).
func (q *QueueConsumer) WithResync(healthy func() bool, handoffs *publisher.OwnerGateHandoffs) {
	q.resyncHealthy = healthy
	q.handoffs = handoffs
}

// resyncAcksOwnerGated reports whether owner_not_anchored outcomes are settled
// by ack because the resync sweep (plan-2607-07/-08) owns their
// reconciliation. Requires the sweep to be configured AND recently healthy —
// a failing sweep must not silently strand acked checkpoints, so the
// pre-existing redelivery contract resumes the moment health lapses.
func (q *QueueConsumer) resyncAcksOwnerGated(status publisher.PublishStatus) bool {
	return q.cfg.ResyncInterval > 0 &&
		q.resyncHealthy != nil && q.resyncHealthy() &&
		status == publisher.StatusOwnerNotAnchored
}

// finish records metrics for a terminal result and acks the message when the
// outcome permits (published / already-anchored / reverted); Retry and
// OwnerNotAnchored are left for redelivery. A StatusReverted (unpublishable)
// result is terminally acked AND alerted at ERROR — the checkpoint is dropped
// from the queue and only self-heals via a later seal (adr-0008), so it warrants
// operator attention (typically a non-conformant encoding, e.g. FOR-377's
// InconsistentReceiptSignature bootstraps).
func (q *QueueConsumer) finish(ctx context.Context, msg QueueMessage, key string, res publisher.PublishResult) {
	// Label reverts by the bounded error name only (raw strings stay in logs).
	reason := ""
	if res.Status == publisher.StatusReverted || res.Status == publisher.StatusRetry {
		reason = publisher.RevertLabel(res.Reason)
	}
	q.metrics.RecordPublish(res.Status.String(), reason)
	// Anchor lag is only meaningful for terminal-success outcomes (P11).
	if (res.Status == publisher.StatusPublished || res.Status == publisher.StatusAlreadyAnchored) &&
		res.SealedSize >= res.OnchainSize {
		q.metrics.SetAnchorLag(
			strconv.FormatUint(res.ChainID, 10), res.Contract.Hex(),
			float64(res.SealedSize-res.OnchainSize))
	}
	attrs := []any{
		"messageID", msg.ID, "key", key, "status", res.Status.String(),
		"chain", res.ChainID, "contract", res.Contract.Hex(),
		"tx", res.TxHash.Hex(), "sealedSize", res.SealedSize,
		"onchainSize", res.OnchainSize, "reason", res.Reason,
	}
	if res.Status == publisher.StatusReverted {
		q.logger.Error("unpublishable checkpoint terminally acked", attrs...)
	} else {
		q.logger.Info("publish result", attrs...)
	}
	if res.ShouldAck() {
		q.ackMsg(ctx, msg)
		return
	}
	if q.resyncAcksOwnerGated(res.Status) {
		if q.handoffs != nil {
			q.handoffs.Record(key)
		}
		q.ackMsg(ctx, msg)
	}
}

// ackMsg acknowledges a queue message and records the ack metric.
func (q *QueueConsumer) ackMsg(ctx context.Context, msg QueueMessage) {
	if err := q.acknowledge(ctx, msg); err != nil {
		q.logger.Warn("ack failed", "messageID", msg.ID, "error", err)
		q.metrics.RecordAck(false)
	} else {
		q.metrics.RecordAck(true)
	}
}

// checkpointKeyFromMessage unwraps the R2 notification and returns the checkpoint
// object key when the message is a PutObject on the checkpoints prefix.
func (q *QueueConsumer) checkpointKeyFromMessage(msg QueueMessage) (string, bool) {
	var bodyJSON string
	if err := json.Unmarshal(msg.Body, &bodyJSON); err != nil {
		q.logger.Warn("unmarshal message body wrapper", "messageID", msg.ID, "error", err)
		return "", false
	}
	var note R2Notification
	if err := json.Unmarshal([]byte(bodyJSON), &note); err != nil {
		q.logger.Warn("unmarshal R2 notification", "messageID", msg.ID, "error", err)
		return "", false
	}
	if note.Action != "PutObject" {
		return "", false
	}
	if _, err := publisher.ParseCheckpointKey(note.Object.Key); err != nil {
		q.logger.Debug("skipping non-checkpoint key", "messageID", msg.ID, "key", note.Object.Key, "error", err)
		return "", false
	}
	return note.Object.Key, true
}

func cloudflareQueueAPIBase(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty queue URL")
	}
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, "/messages")
	return s, nil
}

func (q *QueueConsumer) acknowledge(ctx context.Context, msg QueueMessage) error {
	base, err := cloudflareQueueAPIBase(q.cfg.QueueURL)
	if err != nil {
		return err
	}
	if msg.LeaseID == "" {
		return fmt.Errorf("missing lease_id for message %s", msg.ID)
	}
	type lease struct {
		LeaseID string `json:"lease_id"`
	}
	payload := struct {
		Acks    []lease `json:"acks"`
		Retries []lease `json:"retries"`
	}{Acks: []lease{{msg.LeaseID}}, Retries: []lease{}}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, base+"/messages/ack", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+q.cfg.QueueToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := q.httpClient.Do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("ack failed: status=%d body_sha256=%s", resp.StatusCode, logredact.SHA256Hex(b))
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var ar QueueAckResponse
	if err := json.Unmarshal(b, &ar); err != nil {
		return fmt.Errorf("parse ack response: %w", err)
	}
	if len(ar.Errors) > 0 {
		return fmt.Errorf("ack returned %d error(s)", len(ar.Errors))
	}
	if !ar.Success || ar.Result.AckCount == 0 {
		return fmt.Errorf("ack not applied: success=%v ackCount=%d", ar.Success, ar.Result.AckCount)
	}
	return nil
}
