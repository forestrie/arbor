package consumer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/ranger"
)

// QueueConsumer coordinates Cloudflare Queue message consumption.
type QueueConsumer struct {
	cfg        ranger.Config
	httpClient *ranger.HTTPClient
	logger     *slog.Logger
}

// NewQueueConsumer constructs a QueueConsumer with a config copy and shared HTTP client.
func NewQueueConsumer(cfg ranger.Config, httpClient *ranger.HTTPClient, logger *slog.Logger) *QueueConsumer {
	return &QueueConsumer{
		cfg:        cfg,
		httpClient: httpClient,
		logger:     logger,
	}
}

// ConsumeQueue starts the queue consumer loop that polls for messages.
func (q *QueueConsumer) ConsumeQueue(ctx context.Context) {
	defer q.httpClient.Close()

	ticker := time.NewTicker(q.cfg.PollInterval)
	defer ticker.Stop()

	q.logger.Debug("starting queue consumer",
		"queueURL", q.cfg.QueueURL,
		"pollInterval", q.cfg.PollInterval,
	)

	for {
		select {
		case <-ctx.Done():
			q.logger.Debug("queue consumer stopping")
			return
		case <-ticker.C:
			if err := q.PullAndProcessMessages(ctx); err != nil {
				q.logger.Error("failed to process messages", "error", err)
			}
		}
	}
}

// PullAndProcessMessages pulls messages from the queue and processes them.
func (q *QueueConsumer) PullAndProcessMessages(ctx context.Context) error {
	baseQueueURL := strings.TrimSuffix(q.cfg.QueueURL, "/")
	pullURL := fmt.Sprintf("%s/messages/pull", baseQueueURL)

	payload := struct {
		BatchSize           int `json:"batch_size"`
		VisibilityTimeoutMs int `json:"visibility_timeout_ms,omitempty"`
	}{
		BatchSize:           q.cfg.QueueBatchSize,
		VisibilityTimeoutMs: int(q.cfg.VisibilityTimeout.Milliseconds()),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal pull payload: %w", err)
	}

	req, err := http.NewRequest("POST", pullURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+q.cfg.QueueAPIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := q.httpClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to pull messages: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		q.logger.Warn("queue pull failed",
			"status", resp.StatusCode,
			"body", string(body),
		)
		return fmt.Errorf("pull request failed: status=%d", resp.StatusCode)
	}

	var queueResp QueuePullResponse
	if err := json.NewDecoder(resp.Body).Decode(&queueResp); err != nil {
		q.logger.Warn("failed to decode response", "error", err)
		return fmt.Errorf("failed to decode response: %w", err)
	}

	q.logger.Info("pulled messages",
		"count", len(queueResp.Result.Messages),
		"backlog", queueResp.Result.MessageBacklogCount,
		"pullURL", pullURL,
		"batchSz", q.cfg.QueueBatchSize,
		"visto", q.cfg.VisibilityTimeout.Microseconds(),
	)

	var acknowledged int
	for _, msg := range queueResp.Result.Messages {
		if err := q.ProcessMessage(ctx, msg); err != nil {
			q.logger.Warn("failed to process message - not acknowledging",
				"messageID", msg.ID,
				"error", err,
			)
			continue
		}

		if err := q.AcknowledgeMessage(ctx, msg); err != nil {
			q.logger.Warn("failed to acknowledge message",
				"messageID", msg.ID,
				"error", err,
			)
			continue
		}
		acknowledged++
	}

	if acknowledged != len(queueResp.Result.Messages) {
		q.logger.Info("failed to acknowledge messages", "count", len(queueResp.Result.Messages)-acknowledged)
	}

	return nil
}

// ProcessMessage handles the business logic for a single message.
func (q *QueueConsumer) ProcessMessage(ctx context.Context, msg QueueMessage) error {
	var bodyJSON string
	if err := json.Unmarshal(msg.Body, &bodyJSON); err != nil {
		q.logger.Warn("failed to parse queue message body - message not consumed",
			"messageID", msg.ID,
			"error", err,
		)
		return fmt.Errorf("failed to parse queue message body: %w", err)
	}

	var r2Notification R2Notification
	if err := json.Unmarshal([]byte(bodyJSON), &r2Notification); err != nil {
		q.logger.Warn("failed to parse R2 notification - message not consumed",
			"messageID", msg.ID,
			"error", err,
			"bodySample", samplePrefix(bodyJSON, 128),
		)
		return fmt.Errorf("failed to parse R2 notification: %w", err)
	}

	if r2Notification.Action != "PutObject" {
		return nil
	}

	parsed, err := parseObjectPath(r2Notification.Object.Key)
	if err != nil {
		q.logger.Warn("failed to parse object path - message not consumed",
			"messageID", msg.ID,
			"path", r2Notification.Object.Key,
			"error", err,
		)
		return fmt.Errorf("failed to parse object path %q: %w", r2Notification.Object.Key, err)
	}
	parsed.ETag = r2Notification.Object.ETag
	parsed.EventTime = r2Notification.EventTime

	if !q.cfg.TrustCanopy {
		return nil
	}

	if err := VerifyObjectHash(ctx, q.cfg, parsed, q.httpClient, q.logger); err != nil {
		q.logger.Warn("hash verification failed - message consumed anyway",
			"fenceIndex", parsed.FenceIndex,
			"pathHash", parsed.Hash,
			"error", err,
		)
		return nil
	}

	return nil
}

// AcknowledgeMessage acknowledges a message to remove it from the queue.
func (q *QueueConsumer) AcknowledgeMessage(ctx context.Context, message QueueMessage) error {
	baseQueueURL := strings.TrimSuffix(q.cfg.QueueURL, "/")
	ackURL := fmt.Sprintf("%s/messages/ack", baseQueueURL)

	if message.LeaseID == "" {
		return fmt.Errorf("missing lease_id for message %s", message.ID)
	}

	payload := struct {
		Acks []struct {
			LeaseID string `json:"lease_id"`
		} `json:"acks"`
		Retries []struct {
			LeaseID string `json:"lease_id"`
		} `json:"retries"`
	}{
		Acks: []struct {
			LeaseID string `json:"lease_id"`
		}{
			{LeaseID: message.LeaseID},
		},
		Retries: []struct {
			LeaseID string `json:"lease_id"`
		}{},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal ack payload: %w", err)
	}

	req, err := http.NewRequest("POST", ackURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create ack request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+q.cfg.QueueAPIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := q.httpClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to acknowledge message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("ack request failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return nil
}

// parseObjectPath extracts logId, fenceIndex, and hash from R2 object path.
func parseObjectPath(path string) (*ParsedNotification, error) {
	cleanPath := strings.TrimPrefix(filepath.Clean(path), "/")
	parts := strings.Split(cleanPath, "/")

	if len(parts) < 5 {
		return nil, fmt.Errorf("invalid path format: expected logs/{logId}/leaves/{fenceIndex}/{hash}, got %d segments", len(parts))
	}

	if parts[0] != "logs" {
		return nil, fmt.Errorf("invalid path format: expected 'logs' prefix, got %q", parts[0])
	}
	if parts[2] != "leaves" {
		return nil, fmt.Errorf("invalid path format: expected 'leaves' segment, got %q", parts[2])
	}

	logID := parts[1]
	fenceIndexStr := parts[3]
	hash := parts[4]

	if len(hash) != 64 {
		return nil, fmt.Errorf("invalid hash length: expected 64 hex characters, got %d", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return nil, fmt.Errorf("invalid hash format: not hex-encoded: %w", err)
	}

	fenceIndex, err := strconv.Atoi(fenceIndexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid fenceIndex %q: %w", fenceIndexStr, err)
	}

	return &ParsedNotification{
		LogID:      logID,
		FenceIndex: fenceIndex,
		Hash:       hash,
		Path:       path,
	}, nil
}

func samplePrefix(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max] + "…"
}
