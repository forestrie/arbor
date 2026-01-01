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
	"sync"
	"time"

	"github.com/forestrie/arbor/services/ranger"
	"github.com/google/uuid"
)

// LogGroupCommitter processes a batch of entries for a single log.
type LogGroupCommitter interface {
	CommitLogGroup(ctx context.Context, logId []byte, entries []Entry) (*CommitResult, error)
}

// Consumer polls the forestrie-ingress Durable Object for entries.
// Each consumer instance is responsible for a single shard.
//
// See: arbor/docs/arc-cloudflare-do-ingress.md
type Consumer struct {
	cfg        ranger.Config
	httpClient *ranger.HTTPClient
	logger     *slog.Logger
	committer  LogGroupCommitter
	pollerId   string
	shardIndex int    // Shard index this consumer is responsible for
	pullURL    string // Pre-computed pull URL with shard parameter
	ackURL     string // Pre-computed ack URL with shard parameter
}

// NewConsumer creates a new ingress consumer for a specific shard.
// Use NewShardedConsumers to create consumers for all shards.
func NewConsumer(cfg ranger.Config, httpClient *ranger.HTTPClient, logger *slog.Logger, committer LogGroupCommitter, shardIndex int, pullURL, ackURL string) *Consumer {
	pollerId := cfg.PollerId
	if pollerId == "" {
		pollerId = uuid.New().String()
	}

	return &Consumer{
		cfg:        cfg,
		httpClient: httpClient,
		logger:     logger.With("shard", shardIndex),
		committer:  committer,
		pollerId:   pollerId,
		shardIndex: shardIndex,
		pullURL:    pullURL,
		ackURL:     ackURL,
	}
}

// NewShardedConsumers discovers shards and creates one consumer per shard.
// Returns the consumers and the discovered shard count.
func NewShardedConsumers(
	ctx context.Context,
	cfg ranger.Config,
	httpClientFactory func() *ranger.HTTPClient,
	logger *slog.Logger,
	committer LogGroupCommitter,
) ([]*Consumer, error) {
	discovery := NewShardDiscovery(cfg)
	shardsResp, err := discovery.DiscoverShards(ctx)
	if err != nil {
		return nil, fmt.Errorf("shard discovery failed: %w", err)
	}

	logger.Info("discovered shards",
		"count", shardsResp.Count,
		"pullUrlTemplate", shardsResp.PullURLTemplate,
	)

	// Log per-shard depth for monitoring
	for _, shard := range shardsResp.Shards {
		logger.Info("shard depth",
			"shard", shard.Index,
			"pendingCount", shard.PendingCount,
		)
	}

	consumers := make([]*Consumer, shardsResp.Count)
	for i := 0; i < shardsResp.Count; i++ {
		pullURL := discovery.BuildPullURL(i)
		ackURL := discovery.BuildAckURL(i)
		consumers[i] = NewConsumer(cfg, httpClientFactory(), logger, committer, i, pullURL, ackURL)
	}

	return consumers, nil
}

// defaultBackoffBase is used when PollIntervalMin is 0 and PollIntervalMax/8
// would also be 0. This ensures backoff multiplication always has a non-zero
// starting point.
const defaultBackoffBase = 10 * time.Millisecond

// ConsumeQueue starts the poll loop that consumes entries from the DO queue.
// Uses exponential backoff: resets to min interval on success, doubles on empty.
//
// The backoff logic separates the configured sleep minimum (PollIntervalMin)
// from the backoff base used for multiplication. This allows PollIntervalMin=0
// to mean "immediate re-poll on success" while still supporting exponential
// backoff on empty responses.
func (c *Consumer) ConsumeQueue(ctx context.Context) {
	defer c.httpClient.Close()

	// Compute backoff base: the starting point for exponential backoff.
	// This must be non-zero for multiplication to work.
	backoffBase := c.cfg.PollIntervalMin
	if backoffBase == 0 {
		backoffBase = c.cfg.PollIntervalMax / 8
	}
	if backoffBase == 0 {
		backoffBase = defaultBackoffBase
	}

	c.logger.Info("starting ingress consumer",
		"pullURL", c.pullURL,
		"pollerId", c.pollerId,
		"pollIntervalMin", c.cfg.PollIntervalMin,
		"pollIntervalMax", c.cfg.PollIntervalMax,
		"backoffBase", backoffBase,
		"batchSize", c.cfg.QueueBatchSize,
		"visibilityMs", c.cfg.VisibilityTimeout.Milliseconds(),
	)

	// currentBackoff tracks the current position in the exponential backoff
	// sequence. It is reset to PollIntervalMin on success (which may be 0).
	currentBackoff := c.cfg.PollIntervalMin

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

		var sleepDuration time.Duration
		if hadEntries {
			// Success: sleep for exactly PollIntervalMin (can be 0 for
			// immediate re-poll) and reset backoff state.
			sleepDuration = c.cfg.PollIntervalMin
			currentBackoff = c.cfg.PollIntervalMin
		} else {
			// Empty response: exponential backoff.
			// If currentBackoff is 0, use backoffBase to start the sequence
			// (since 0 * 2 = 0 would never increase).
			if currentBackoff == 0 {
				currentBackoff = backoffBase
			} else {
				currentBackoff *= 2
			}
			if currentBackoff > c.cfg.PollIntervalMax {
				currentBackoff = c.cfg.PollIntervalMax
			}
			sleepDuration = currentBackoff
		}

		// Add jitter: ±10% of sleep duration (only if non-zero).
		if sleepDuration > 0 {
			jitter := time.Duration(rand.Int63n(int64(sleepDuration) / 5))
			jitter -= sleepDuration / 10 // center the jitter around zero
			sleepDuration += jitter
		}

		// Always yield to the scheduler, even if sleepDuration is 0.
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

	result, err := c.committer.CommitLogGroup(ctx, group.LogId, group.Entries)
	if err != nil {
		c.logger.Warn("commit failed",
			"logId", logIdHex,
			"entries", len(group.Entries),
			"error", err,
		)
		// Don't ack; entries will redeliver after visibility timeout.
		return
	}

	if result == nil || result.Committed == 0 {
		c.logger.Debug("no entries committed",
			"logId", logIdHex,
		)
		return
	}

	c.logger.Info("committed entries",
		"logId", logIdHex,
		"committed", result.Committed,
		"total", len(group.Entries),
		"firstLeafIndex", result.FirstLeafIndex,
	)

	// Ack using limit-based ack with sequencing metadata.
	// See: arbor/docs/arc-cloudflare-do-ingress.md section 2.3 and 3.12
	if err := c.ackFirst(ctx, group.LogId, group.SeqLo, result); err != nil {
		// IMPORTANT: Entries were committed but ack failed.
		// They will redeliver and may cause duplicate commits.
		// See arc-cloudflare-do-ingress.md section 3.8 and 3.10 for
		// accepted risk analysis and future mitigation options.
		c.logger.Warn("ack failed after commit",
			"logId", logIdHex,
			"seqLo", group.SeqLo,
			"committed", result.Committed,
			"error", err,
		)
	}
}

// pull fetches entries from the DO queue shard.
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

	// Use pre-computed URL with shard parameter
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.pullURL, bytes.NewReader(body))
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
// Includes sequencing metadata (firstLeafIndex, massifIndex) for return path unification.
func (c *Consumer) ackFirst(ctx context.Context, logId []byte, seqLo uint64, result *CommitResult) error {
	if c.cfg.SuppressAcknowledge {
		return nil
	}

	req := AckRequest{
		LogId:          logId,
		SeqLo:          seqLo,
		Limit:          uint64(result.Committed),
		FirstLeafIndex: result.FirstLeafIndex,
		MassifHeight:   uint64(c.cfg.MassifHeight),
	}

	body, err := EncodeAckRequest(req)
	if err != nil {
		return fmt.Errorf("encode ack request: %w", err)
	}

	// Use pre-computed URL with shard parameter
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.ackURL, bytes.NewReader(body))
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
