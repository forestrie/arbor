package consumer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
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
	leaseMgr   *sealer.DelegationLeaseManager
}

type logWork struct {
	logIDBytes   []byte
	massifHeight uint8
	messages     []QueueMessage
}

// NewQueueConsumer constructs a QueueConsumer with a config copy and shared HTTP client.
func NewQueueConsumer(cfg sealer.Config, httpClient *sealer.HTTPClient, logger *slog.Logger, leaseMgr *sealer.DelegationLeaseManager) *QueueConsumer {
	return &QueueConsumer{
		cfg:        cfg,
		httpClient: httpClient,
		logger:     logger,
		leaseMgr:   leaseMgr,
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
	unique := make(map[string]*logWork)
	var invalidMessages []QueueMessage

	for _, msg := range qbatch.Messages {
		var bodyJSON string
		if err := json.Unmarshal(msg.Body, &bodyJSON); err != nil {
			q.logger.Warn("failed to unmarshal message body wrapper", "messageID", msg.ID, "error", err)
			invalidMessages = append(invalidMessages, msg)
			continue
		}

		var note R2Notification
		if err := json.Unmarshal([]byte(bodyJSON), &note); err != nil {
			q.logger.Warn("failed to unmarshal R2 notification", "messageID", msg.ID, "error", err)
			invalidMessages = append(invalidMessages, msg)
			continue
		}

		if note.Action != "PutObject" {
			q.logger.Debug("skipping non-PutObject notification", "messageID", msg.ID, "action", note.Action)
			invalidMessages = append(invalidMessages, msg)
			continue
		}

		logID, massifHeight, err := parseLogIDAndMassifHeightFromObjectPath(note.Object.Key)
		if err != nil {
			q.logger.Warn("failed to parse object key", "messageID", msg.ID, "key", note.Object.Key, "error", err)
			invalidMessages = append(invalidMessages, msg)
			continue
		}

		u, err := uuid.FromBytes(logID)
		if err != nil {
			q.logger.Warn("failed to format logID", "messageID", msg.ID, "error", err)
			invalidMessages = append(invalidMessages, msg)
			continue
		}

		key := u.String()
		w, ok := unique[key]
		if !ok {
			w = &logWork{
				logIDBytes:   logID,
				massifHeight: massifHeight,
			}
			unique[key] = w
		} else if w.massifHeight != massifHeight {
			q.logger.Warn("inconsistent massif height for log within batch",
				"logID", key,
				"prevHeight", w.massifHeight,
				"newHeight", massifHeight,
				"messageID", msg.ID,
			)
			invalidMessages = append(invalidMessages, msg)
			continue
		}
		w.messages = append(w.messages, msg)
	}

	// Log a concise summary; avoid dumping a large set into logs.
	q.logger.Info("sealer poll summary",
		"messages", len(qbatch.Messages),
		"uniqueLogs", len(unique),
		"sampleLogIDs", sampleKeysFromWork(unique, 5),
		"invalidMessages", len(invalidMessages),
	)

	// Always ack invalid/unprocessable messages so they don't poison the queue.
	if len(invalidMessages) > 0 {
		q.ackAll(ctx, invalidMessages)
	}

	if len(unique) == 0 {
		return nil
	}

	// Acquire a delegation signer token once per batch.
	token, err := sealer.AcquireDelegationSignerAccessToken(ctx, q.cfg.DelegationSignerServiceAccountEmail)
	if err != nil {
		return fmt.Errorf("failed to obtain delegation signer access token: %w", err)
	}

	svc := sealer.SealerService{
		Cfg:          q.cfg,
		HTTPClient:   q.httpClient,
		Logger:       q.logger,
		LeaseManager: q.leaseMgr,
	}
	batchCtx := sealer.SealerBatch{
		DelegationAccessToken: token.AccessToken,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	failures := 0

	for _, w := range unique {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sealer.CheckpointLog(ctx, svc, batchCtx, w.logIDBytes, w.massifHeight); err != nil {
				if errors.Is(err, sealer.ErrDelegationExpired) {
					// Expected retry path: do not ack messages for this log so the queue will redeliver.
					q.logger.Info("log checkpointing aborted due to expiring delegation; will retry",
						"logID", keyFromLogIDBytes(w.logIDBytes),
						"massifHeight", w.massifHeight,
						"error", err,
					)
					return
				}
				mu.Lock()
				failures++
				mu.Unlock()
				q.logger.Warn("log checkpointing failed", "logID", keyFromLogIDBytes(w.logIDBytes), "massifHeight", w.massifHeight, "error", err)
				// Don't ack messages for this log; they will be retried after visibility timeout.
				return
			}
			// Ack only messages for successfully checkpointed logs.
			q.ackAll(ctx, w.messages)
		}()
	}

	wg.Wait()
	if failures > 0 {
		return fmt.Errorf("sealing failed for %d log(s)", failures)
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

	// Expected format: v2/merklelog/massifs/{massifID}/{logID}/{index}.log
	// Example: v2/merklelog/massifs/14/3062ea57-c184-41d8-bd61-296b02c680d8/0000000000000000.log
	if len(parts) < 6 {
		return nil, fmt.Errorf("invalid path format: expected v2/merklelog/massifs/{massifID}/{logID}/{index}.log, got %d segments", len(parts))
	}
	if parts[0] != "v2" {
		return nil, fmt.Errorf("invalid path format: expected 'v2' prefix, got %q", parts[0])
	}
	if parts[1] != "merklelog" {
		return nil, fmt.Errorf("invalid path format: expected 'merklelog' segment, got %q", parts[1])
	}
	if parts[2] != "massifs" {
		return nil, fmt.Errorf("invalid path format: expected 'massifs' segment, got %q", parts[2])
	}

	// parts[3] is the massifID (e.g., "14")
	// parts[4] is the logID (UUID format)
	// parts[5] is the index file (e.g., "0000000000000000.log")

	uid, err := uuid.Parse(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid logID format at position 4: %w", err)
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

func parseLogIDAndMassifHeightFromObjectPath(path string) ([]byte, uint8, error) {
	cleanPath := strings.TrimPrefix(filepath.Clean(path), "/")
	parts := strings.Split(cleanPath, "/")

	// Expected format: v2/merklelog/massifs/{massifHeight}/{logID}/{index}.log
	if len(parts) < 6 {
		return nil, 0, fmt.Errorf("invalid path format: expected v2/merklelog/massifs/{massifHeight}/{logID}/{index}.log, got %d segments", len(parts))
	}
	if parts[0] != "v2" {
		return nil, 0, fmt.Errorf("invalid path format: expected 'v2' prefix, got %q", parts[0])
	}
	if parts[1] != "merklelog" {
		return nil, 0, fmt.Errorf("invalid path format: expected 'merklelog' segment, got %q", parts[1])
	}
	if parts[2] != "massifs" {
		return nil, 0, fmt.Errorf("invalid path format: expected 'massifs' segment, got %q", parts[2])
	}

	h64, err := strconv.ParseUint(parts[3], 10, 8)
	if err != nil || h64 == 0 {
		return nil, 0, fmt.Errorf("invalid massif height %q", parts[3])
	}
	massifHeight := uint8(h64)

	uid, err := uuid.Parse(parts[4])
	if err != nil {
		return nil, 0, fmt.Errorf("invalid logID format at position 4: %w", err)
	}

	return uid[:], massifHeight, nil
}

func sampleKeysFromWork(m map[string]*logWork, max int) []string {
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

func keyFromLogIDBytes(b []byte) string {
	u, err := uuid.FromBytes(b)
	if err != nil {
		return fmt.Sprintf("%x", b)
	}
	return u.String()
}
