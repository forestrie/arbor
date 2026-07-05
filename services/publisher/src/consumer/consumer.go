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
		backoffBase = q.cfg.PollIntervalMax / 8
	}
	if backoffBase == 0 {
		backoffBase = defaultBackoffBase
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
		if sleep > 0 {
			jitter := time.Duration(rand.Int63n(int64(sleep)/5)) - sleep/10
			sleep += jitter
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

// processBatch publishes each message's checkpoint concurrently and acks the
// terminal ones. The ChainWriter serialises per-chain nonces, so concurrent
// publishes across logs are safe.
func (q *QueueConsumer) processBatch(ctx context.Context, msgs []QueueMessage) {
	if len(msgs) == 0 {
		return
	}
	q.metrics.AddMessagesProcessed(len(msgs))

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		toAck []QueueMessage
	)
	for _, msg := range msgs {
		msg := msg
		wg.Add(1)
		go func() {
			defer wg.Done()
			if q.handleMessage(ctx, msg) {
				mu.Lock()
				toAck = append(toAck, msg)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	q.ackAll(ctx, toAck)
}

// handleMessage returns true when the message should be acked.
func (q *QueueConsumer) handleMessage(ctx context.Context, msg QueueMessage) bool {
	key, ok := q.checkpointKeyFromMessage(msg)
	if !ok {
		// Not a checkpoint PutObject we can act on — ack to avoid poisoning.
		return true
	}

	start := time.Now()
	res, err := q.pub.Publish(ctx, key)
	q.metrics.ObservePublishDuration(time.Since(start).Seconds())
	if err != nil {
		// Unexpected infra failure: leave unacked for redelivery.
		q.logger.Warn("publish failed", "messageID", msg.ID, "key", key, "error", err)
		return false
	}

	reason := ""
	if res.Status == publisher.StatusReverted {
		reason = res.Reason
	}
	q.metrics.RecordPublish(res.Status.String(), reason)
	if res.SealedSize >= res.OnchainSize {
		q.metrics.SetAnchorLag(
			strconv.FormatUint(res.ChainID, 10), res.Contract.Hex(),
			float64(res.SealedSize-res.OnchainSize))
	}

	q.logger.Info("publish result",
		"messageID", msg.ID, "key", key, "status", res.Status.String(),
		"chain", res.ChainID, "contract", res.Contract.Hex(),
		"tx", res.TxHash.Hex(), "sealedSize", res.SealedSize,
		"onchainSize", res.OnchainSize, "reason", res.Reason)
	return res.ShouldAck()
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

func (q *QueueConsumer) ackAll(ctx context.Context, msgs []QueueMessage) {
	var wg sync.WaitGroup
	for _, msg := range msgs {
		msg := msg
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := q.acknowledge(ctx, msg); err != nil {
				q.logger.Warn("ack failed", "messageID", msg.ID, "error", err)
				q.metrics.RecordAck(false)
			} else {
				q.metrics.RecordAck(true)
			}
		}()
	}
	wg.Wait()
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
