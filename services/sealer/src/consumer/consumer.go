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
	"strings"
	"sync"
	"time"

	"github.com/forestrie/arbor/services/sealer"
	"github.com/google/uuid"
)

// QueueConsumer coordinates Cloudflare Queue message consumption.
type QueueConsumer struct {
	cfg        sealer.Config
	httpClient *sealer.HTTPClient
	logger     *slog.Logger
}

// NewQueueConsumer constructs a QueueConsumer with a config copy and shared HTTP client.
func NewQueueConsumer(cfg sealer.Config, httpClient *sealer.HTTPClient, logger *slog.Logger) *QueueConsumer {
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
				q.logger.Error("failed to pull/process messages", "error", err)
			}
		}
	}
}

// PullAndProcessMessages pulls messages from the queue, extracts log IDs, and acknowledges messages.
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
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		q.logger.Warn("queue pull failed", "status", resp.StatusCode, "body", string(b))
		return fmt.Errorf("pull request failed: status=%d", resp.StatusCode)
	}

	var queueResp QueuePullResponse
	if err := json.NewDecoder(resp.Body).Decode(&queueResp); err != nil {
		q.logger.Warn("failed to decode queue pull response", "error", err)
		return fmt.Errorf("failed to decode response: %w", err)
	}

	q.logger.Info("pulled messages",
		"count", len(queueResp.Result.Messages),
		"backlog", queueResp.Result.MessageBacklogCount,
		"pullURL", pullURL,
		"batchSz", q.cfg.QueueBatchSize,
		"visto", q.cfg.VisibilityTimeout.Microseconds(),
	)

	return q.ProcessAndAcknowledge(ctx, &queueResp.Result)
}

// ProcessAndAcknowledge extracts the set of unique log IDs referenced by messages.
// It acknowledges all messages regardless of decode/parsing errors.
func (q *QueueConsumer) ProcessAndAcknowledge(ctx context.Context, qbatch *QueuePullResult) error {
	uniqueLogIDs := make(map[string]struct{})

	for _, msg := range qbatch.Messages {
		var bodyJSON string
		if err := json.Unmarshal(msg.Body, &bodyJSON); err != nil {
			q.logger.Warn("failed to unmarshal message body wrapper", "messageID", msg.ID, "error", err)
			continue
		}

		var note R2Notification
		if err := json.Unmarshal([]byte(bodyJSON), &note); err != nil {
			q.logger.Warn("failed to unmarshal R2 notification", "messageID", msg.ID, "error", err)
			continue
		}

		if note.Action != "PutObject" {
			q.logger.Debug("skipping non-PutObject notification", "messageID", msg.ID, "action", note.Action)
			continue
		}

		logID, err := parseLogIDFromObjectPath(note.Object.Key)
		if err != nil {
			q.logger.Warn("failed to parse object key", "messageID", msg.ID, "key", note.Object.Key, "error", err)
			continue
		}

		u, err := uuid.FromBytes(logID)
		if err != nil {
			q.logger.Warn("failed to format logID", "messageID", msg.ID, "error", err)
			continue
		}
		uniqueLogIDs[u.String()] = struct{}{}
	}

	// Log a concise summary; avoid dumping a large set into logs.
	q.logger.Info("sealer poll summary",
		"messages", len(qbatch.Messages),
		"uniqueLogs", len(uniqueLogIDs),
		"sampleLogIDs", sampleKeys(uniqueLogIDs, 5),
	)

	q.ackAll(ctx, qbatch.Messages)
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
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("ack request failed: status=%d, body=%s", resp.StatusCode, string(b))
	}

	// Read the response body first, then decode it
	// This allows us to log the raw body if parsing fails
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		q.logger.Warn("failed to read ack response body", "messageID", message.ID, "error", err)
		return fmt.Errorf("failed to read ack response body: %w", err)
	}

	// Parse and validate the response body to ensure acknowledgment actually succeeded
	var ackResp QueueAckResponse
	if err := json.Unmarshal(bodyBytes, &ackResp); err != nil {
		// If we can't parse the response, log it with the raw body
		q.logger.Warn("failed to parse ack response", "messageID", message.ID, "error", err, "body", string(bodyBytes))
		return fmt.Errorf("failed to parse ack response: %w", err)
	}

	// Check for errors in the response
	if len(ackResp.Errors) > 0 {
		for _, e := range ackResp.Errors {
			q.logger.Warn("ack response error", "messageID", message.ID, "code", e.Code, "message", e.Message)
		}
		return fmt.Errorf("ack request returned errors: %d error(s)", len(ackResp.Errors))
	}

	// Check the success field
	if !ackResp.Success {
		q.logger.Warn("ack request failed", "messageID", message.ID, "success", ackResp.Success, "ackCount", ackResp.Result.AckCount)
		return fmt.Errorf("ack request failed: success=false, ackCount=%d", ackResp.Result.AckCount)
	}

	// Check that at least one message was acknowledged
	if ackResp.Result.AckCount == 0 {
		q.logger.Warn("no messages acknowledged", "messageID", message.ID, "ackCount", ackResp.Result.AckCount)
		return fmt.Errorf("no messages acknowledged: ackCount=0")
	}

	// Log any warnings from the response (if it's a string array)
	if warnings, ok := ackResp.Result.Warnings.([]interface{}); ok {
		for _, w := range warnings {
			if warningStr, ok := w.(string); ok {
				q.logger.Warn("ack response warning", "messageID", message.ID, "warning", warningStr)
			}
		}
	}

	return nil
}

func (q *QueueConsumer) ackAll(ctx context.Context, messages []QueueMessage) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	failureCount := 0

	for _, msg := range messages {
		msg := msg
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := q.AcknowledgeMessage(ctx, msg); err != nil {
				mu.Lock()
				failureCount++
				mu.Unlock()
				q.logger.Warn("failed to acknowledge message", "messageID", msg.ID, "error", err)
			}
		}()
	}

	wg.Wait()
	successCount := len(messages) - failureCount
	q.logger.Info("acknowledged messages",
		"count", successCount,
		"total", len(messages),
		"failed", failureCount,
	)
}

func parseLogIDFromObjectPath(path string) ([]byte, error) {
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

	uid, err := uuid.Parse(parts[1])
	if err != nil {
		return nil, err
	}

	// Optional validation: ensure the hash segment looks like hex.
	hash := parts[4]
	if len(hash) != 64 {
		return nil, fmt.Errorf("invalid hash length: expected 64 hex characters, got %d", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return nil, fmt.Errorf("invalid hash format: not hex-encoded: %w", err)
	}

	return uid[:], nil
}

func sampleKeys(m map[string]struct{}, max int) []string {
	if max <= 0 {
		return nil
	}
	out := make([]string, 0, max)
	for k := range m {
		out = append(out, k)
		if len(out) >= max {
			break
		}
	}
	return out
}
