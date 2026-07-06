// Package consumer is the publisher's Cloudflare Queue pull consumer. It polls
// the checkpoints-prefix queue, turns each R2 PutObject notification into a
// one-shot publish, and acks only the messages whose outcome is terminal
// (published / already-anchored / deterministic revert). Transient outcomes
// (owner-not-anchored, unconfigured chain, infra error) are left unacked so the
// visibility timeout redelivers them — that redelivery is the reconciliation
// mechanism (mirrors the sealer's ErrDelegationPending non-ack path).
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

	"github.com/forestrie/arbor/services/pkgs/logredact"
	"github.com/forestrie/arbor/services/publisher"
	"github.com/forestrie/arbor/services/publisher/metrics"
)

// QueueConsumer coordinates Cloudflare Queue message consumption for the publisher.
type QueueConsumer struct {
	cfg        publisher.Config
	httpClient *publisher.HTTPClient
	logger     *slog.Logger
	pub        *publisher.Publisher
	metrics    *metrics.Metrics
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
		wg    sync.WaitGroup
		mu    sync.Mutex
		ready []publisher.AssembledPublish
	)
	for _, g := range groups {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			if req, ok := q.assembleGroup(ctx, g); ok {
				mu.Lock()
				ready = append(ready, req)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(ready) > 0 {
		// Returns once sends are admitted; acks fire async from the collector.
		q.pub.SubmitBatch(ctx, ready)
	}
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

// assembleGroup runs the read phase for a log's primary. It returns a
// ready-to-send AssembledPublish (ok=true) whose Ack finalises the primary and
// its subsumed siblings when the receipt resolves; otherwise it settles here.
func (q *QueueConsumer) assembleGroup(ctx context.Context, g logGroup) (publisher.AssembledPublish, bool) {
	start := time.Now()
	calldata, res, ready, err := q.pub.Assemble(ctx, g.key)
	if err != nil {
		q.metrics.ObservePublishDuration(time.Since(start).Seconds())
		q.logger.Warn("assemble failed", "messageID", g.primary.ID, "key", g.key, "error", err)
		return publisher.AssembledPublish{}, false // leave primary + siblings unacked
	}
	if !ready {
		q.metrics.ObservePublishDuration(time.Since(start).Seconds())
		q.finishGroup(ctx, g, res)
		return publisher.AssembledPublish{}, false
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
	}, true
}

// finishGroup settles a log's primary and, on a terminal-success outcome, acks
// its subsumed siblings too (the anchored highest seal covers their lower
// massifs via the consistency chain). On retry, siblings are left unacked and
// redeliver with the primary.
func (q *QueueConsumer) finishGroup(ctx context.Context, g logGroup, res publisher.PublishResult) {
	q.finish(ctx, g.primary, g.key, res)
	if res.ShouldAck() {
		for _, sib := range g.siblings {
			q.ackMsg(ctx, sib)
		}
	}
}

// finish records metrics for a terminal result and acks the message when the
// outcome permits (published / already-anchored / superseded); transient
// and unsubmitted outcomes are left for redelivery.
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
	q.logger.Info("publish result",
		"messageID", msg.ID, "key", key, "status", res.Status.String(),
		"chain", res.ChainID, "contract", res.Contract.Hex(),
		"tx", res.TxHash.Hex(), "sealedSize", res.SealedSize,
		"onchainSize", res.OnchainSize, "reason", res.Reason)
	if res.ShouldAck() {
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
