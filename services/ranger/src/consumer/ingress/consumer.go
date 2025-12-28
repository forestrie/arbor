package ingress

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/forestrie/arbor/services/ranger"
	"github.com/google/uuid"
)

// LogGroupCommitter processes a batch of entries for a single log.
type LogGroupCommitter interface {
	CommitLogGroup(ctx context.Context, logId []byte, entries []Entry) (int, error)
}

// Consumer polls the forestrie-ingress Durable Object for entries.
//
// See: arbor/docs/arc-cloudflare-do-ingress.md
type Consumer struct {
	cfg        ranger.Config
	httpClient *ranger.HTTPClient
	logger     *slog.Logger
	committer  LogGroupCommitter
	pollerId   string
}

// NewConsumer creates a new ingress consumer.
func NewConsumer(cfg ranger.Config, httpClient *ranger.HTTPClient, logger *slog.Logger, committer LogGroupCommitter) *Consumer {
	pollerId := cfg.PollerId
	if pollerId == "" {
		pollerId = uuid.New().String()
	}

	return &Consumer{
		cfg:        cfg,
		httpClient: httpClient,
		logger:     logger,
		committer:  committer,
		pollerId:   pollerId,
	}
}

// ConsumeQueue starts the poll loop that consumes entries from the DO queue.
// Uses exponential backoff: resets to min interval on success, doubles on empty.
func (c *Consumer) ConsumeQueue(ctx context.Context) {
	defer c.httpClient.Close()

	c.logger.Info("starting ingress consumer",
		"queueURL", c.cfg.QueueURL,
		"pollerId", c.pollerId,
		"pollIntervalMin", c.cfg.PollIntervalMin,
		"pollIntervalMax", c.cfg.PollIntervalMax,
		"batchSize", c.cfg.QueueBatchSize,
		"visibilityMs", c.cfg.VisibilityTimeout.Milliseconds(),
	)

	currentInterval := c.cfg.PollIntervalMin

	for {
		select {
		case <-ctx.Done():
			c.logger.Debug("ingress consumer stopping")
			return
		default:
		}

		hadEntries, err := c.pollCycle(ctx)
		if err != nil {
			c.logger.Error("poll cycle failed", "error", err)
		}

		if hadEntries {
			// Reset to minimum interval on success
			currentInterval = c.cfg.PollIntervalMin
		} else {
			// Double interval on empty response (exponential backoff)
			currentInterval *= 2
			if currentInterval > c.cfg.PollIntervalMax {
				currentInterval = c.cfg.PollIntervalMax
			}
		}

		// Add jitter: ±10% of current interval
		jitter := time.Duration(rand.Int63n(int64(currentInterval) / 5))
		jitter -= currentInterval / 10 // center the jitter around zero
		sleepDuration := currentInterval + jitter

		select {
		case <-ctx.Done():
			c.logger.Debug("ingress consumer stopping")
			return
		case <-time.After(sleepDuration):
		}
	}
}

// pollCycle pulls entries from the DO and processes them.
// Returns true if entries were processed, false if queue was empty.
func (c *Consumer) pollCycle(ctx context.Context) (bool, error) {
	resp, err := c.pull(ctx)
	if err != nil {
		return false, err
	}

	if len(resp.LogGroups) == 0 {
		c.logger.Debug("no entries to process")
		return false, nil
	}

	c.logger.Info("pulled entries",
		"logGroups", len(resp.LogGroups),
		"leaseExpiry", resp.LeaseExpiry,
	)

	// Process each log group in parallel
	var wg sync.WaitGroup
	for _, group := range resp.LogGroups {
		wg.Add(1)
		go func(g LogGroup) {
			defer wg.Done()
			c.processLogGroup(ctx, g)
		}(group)
	}
	wg.Wait()

	return true, nil
}

// processLogGroup commits entries for a single log and acks them.
func (c *Consumer) processLogGroup(ctx context.Context, group LogGroup) {
	logIdHex := hex.EncodeToString(group.LogId)

	committed, err := c.committer.CommitLogGroup(ctx, group.LogId, group.Entries)
	if err != nil {
		c.logger.Warn("commit failed",
			"logId", logIdHex,
			"entries", len(group.Entries),
			"error", err,
		)
		// Don't ack; entries will redeliver after visibility timeout.
		return
	}

	if committed == 0 {
		c.logger.Debug("no entries committed",
			"logId", logIdHex,
		)
		return
	}

	c.logger.Info("committed entries",
		"logId", logIdHex,
		"committed", committed,
		"total", len(group.Entries),
	)

	// Ack using limit-based ack.
	// See: arbor/docs/arc-cloudflare-do-ingress.md section 2.3
	if err := c.ackFirst(ctx, group.LogId, group.SeqLo, committed); err != nil {
		// IMPORTANT: Entries were committed but ack failed.
		// They will redeliver and may cause duplicate commits.
		// See arc-cloudflare-do-ingress.md section 3.8 and 3.10 for
		// accepted risk analysis and future mitigation options.
		c.logger.Warn("ack failed after commit",
			"logId", logIdHex,
			"seqLo", group.SeqLo,
			"committed", committed,
			"error", err,
		)
	}
}

// pull fetches entries from the DO queue.
func (c *Consumer) pull(ctx context.Context) (*PullResponse, error) {
	req := PullRequest{
		PollerId:     c.pollerId,
		BatchSize:    c.cfg.QueueBatchSize,
		VisibilityMs: int(c.cfg.VisibilityTimeout.Milliseconds()),
	}

	body, err := EncodePullRequest(req)
	if err != nil {
		return nil, fmt.Errorf("encode pull request: %w", err)
	}

	url := strings.TrimSuffix(c.cfg.QueueURL, "/") + "/queue/pull"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create pull request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.QueueToken)
	httpReq.Header.Set("Content-Type", "application/cbor")

	httpResp, err := c.httpClient.Do(ctx, httpReq)
	if err != nil {
		return nil, fmt.Errorf("pull request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1024))
		return nil, fmt.Errorf("pull returned status %d: %s", httpResp.StatusCode, string(respBody))
	}

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read pull response: %w", err)
	}

	return DecodePullResponse(respBody)
}

// ackFirst acknowledges committed entries using limit-based ack.
func (c *Consumer) ackFirst(ctx context.Context, logId []byte, seqLo uint64, limit int) error {
	if c.cfg.SuppressAcknowledge {
		return nil
	}

	req := AckRequest{
		LogId: logId,
		SeqLo: seqLo,
		Limit: uint64(limit),
	}

	body, err := EncodeAckRequest(req)
	if err != nil {
		return fmt.Errorf("encode ack request: %w", err)
	}

	url := strings.TrimSuffix(c.cfg.QueueURL, "/") + "/queue/ack"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create ack request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.QueueToken)
	httpReq.Header.Set("Content-Type", "application/cbor")

	httpResp, err := c.httpClient.Do(ctx, httpReq)
	if err != nil {
		return fmt.Errorf("ack request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1024))
		return fmt.Errorf("ack returned status %d: %s", httpResp.StatusCode, string(respBody))
	}

	return nil
}
