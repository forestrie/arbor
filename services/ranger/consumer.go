package ranger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
)

// CloudflareQueueMessage represents a message from Cloudflare Queue
type CloudflareQueueMessage struct {
	ID          string            `json:"id"`
	TimestampMs int64             `json:"timestamp_ms"`
	Body        json.RawMessage   `json:"body"`
	Attempts    int               `json:"attempts"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	LeaseID     string            `json:"lease_id,omitempty"`
}

// CloudflareQueueResponse represents the pull response
type CloudflareQueuePullResponse struct {
	Success  bool                      `json:"success"`
	Errors   []json.RawMessage         `json:"errors"`
	Messages []json.RawMessage         `json:"messages"`
	Result   CloudflareQueuePullResult `json:"result"`
}

// CloudflareQueuePullResult contains the actual messages and metadata for a pull
type CloudflareQueuePullResult struct {
	MessageBacklogCount int                      `json:"message_backlog_count"`
	Messages            []CloudflareQueueMessage `json:"messages"`
}

// R2Notification represents the message format from R2 event notifications
type R2Notification struct {
	Account   string   `json:"account"`
	Action    string   `json:"action"`
	Bucket    string   `json:"bucket"`
	Object    R2Object `json:"object"`
	EventTime string   `json:"eventTime"`
}

// R2Object represents the object information in R2 notifications
type R2Object struct {
	Key  string `json:"key"`
	Size int64  `json:"size"`
	ETag string `json:"eTag"`
}

// ParsedNotification contains extracted data from R2 notification
type ParsedNotification struct {
	LogID      string
	FenceIndex int
	Hash       string // SHA256 hash from path
	Path       string // Full object path
	ETag       string
	EventTime  string
}

// ConsumeQueue starts the queue consumer loop that polls for messages
func ConsumeQueue(ctx context.Context, cfg Config, httpClient *HTTPClient, logger *slog.Logger) {
	defer httpClient.Close()

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	logger.Debug("starting queue consumer",
		"queueURL", cfg.QueueURL,
		"pollInterval", cfg.PollInterval,
	)

	for {
		select {
		case <-ctx.Done():
			logger.Debug("queue consumer stopping")
			return
		case <-ticker.C:
			if err := PullAndProcessMessages(ctx, cfg, httpClient, logger); err != nil {
				logger.Error("failed to process messages", "error", err)
			}
		}
	}
}

// PullAndProcessMessages pulls messages from the queue and processes them
func PullAndProcessMessages(ctx context.Context, cfg Config, httpClient *HTTPClient, logger *slog.Logger) error {
	baseQueueURL := strings.TrimSuffix(cfg.QueueURL, "/")
	// Build pull request URL
	pullURL := fmt.Sprintf("%s/messages/pull", baseQueueURL)

	payload := struct {
		BatchSize           int `json:"batch_size"`
		VisibilityTimeoutMs int `json:"visibility_timeout_ms,omitempty"`
	}{
		BatchSize:           cfg.QueueBatchSize,
		VisibilityTimeoutMs: int(cfg.VisibilityTimeout.Milliseconds()),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal pull payload: %w", err)
	}

	req, err := http.NewRequest("POST", pullURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.QueueAPIToken)
	req.Header.Set("Content-Type", "application/json")

	// Use HTTPClient.Do which handles connection pooling and errors
	// Note: resp.Body.Close() returns the connection to the pool for reuse (if keep-alive)
	// We don't need to explicitly close connections - Transport manages this automatically
	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to pull messages: %w", err)
	}
	defer resp.Body.Close() // Closes response body and returns connection to pool

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		logger.Warn("queue pull failed",
			"status", resp.StatusCode,
			"body", string(body),
		)
		return fmt.Errorf("pull request failed: status=%d", resp.StatusCode)
	}

	var queueResp CloudflareQueuePullResponse
	if err := json.NewDecoder(resp.Body).Decode(&queueResp); err != nil {
		logger.Warn("failed to decode response", "error", err)
		return fmt.Errorf("failed to decode response: %w", err)
	}

	logger.Info("pulled messages",
		"count", len(queueResp.Result.Messages),
		"backlog", queueResp.Result.MessageBacklogCount,
		"pullURL", pullURL,
		"batchSz", cfg.QueueBatchSize,
		"visto", cfg.VisibilityTimeout.Microseconds(),
	)

	// Process each message
	for _, msg := range queueResp.Result.Messages {
		// Process message - only ack if no error returned
		// Non-nil error means message couldn't be consumed
		if err := ProcessMessage(ctx, cfg, httpClient, msg, logger); err != nil {
			logger.Warn("failed to process message - not acknowledging",
				"messageID", msg.ID,
				"error", err,
			)
			// Don't acknowledge - message will be retried or sent to DLQ
			continue
		}

		// Message processed successfully - acknowledge to consume from queue
		if err := AcknowledgeMessage(ctx, cfg, httpClient, msg.ID); err != nil {
			logger.Warn("failed to acknowledge message",
				"messageID", msg.ID,
				"error", err,
			)
		}
		logger.Info("acknowledged message", "messageID", msg.ID)
	}

	return nil
}

// ProcessMessage handles the business logic for a single message
// Returns non-nil error if message could not be consumed (should not be acknowledged)
// Returns nil if message was processed successfully (should be acknowledged)
func ProcessMessage(ctx context.Context, cfg Config, httpClient *HTTPClient, msg CloudflareQueueMessage, logger *slog.Logger) error {
	// Cloudflare HTTP pull delivers the body as a base64-encoded string.
	// First, decode the JSON string, then unmarshal the underlying notification.
	var encodedBody string
	if err := json.Unmarshal(msg.Body, &encodedBody); err != nil {
		logger.Warn("failed to parse queue message body - message not consumed",
			"messageID", msg.ID,
			"error", err,
		)
		return fmt.Errorf("failed to parse queue message body: %w", err)
	}

	decodedBody, err := base64.StdEncoding.DecodeString(encodedBody)
	if err != nil {
		logger.Warn("failed to decode queue message body - message not consumed",
			"messageID", msg.ID,
			"error", err,
			"bodySample", samplePrefix(encodedBody, 64),
		)
		return fmt.Errorf("failed to decode queue message body: %w", err)
	}

	// Parse R2 notification from decoded message body
	var r2Notification R2Notification
	if err := json.Unmarshal(decodedBody, &r2Notification); err != nil {
		logger.Warn("failed to parse R2 notification - message not consumed",
			"messageID", msg.ID,
			"error", err,
		)
		return fmt.Errorf("failed to parse R2 notification: %w", err)
	}

	// Only process object-create events
	// Other events are ignored and message is consumed
	if r2Notification.Action != "PutObject" {
		return nil
	}

	// Parse path to extract logId, fenceIndex, and hash
	// If this fails, we can't process the message - don't consume it
	parsed, err := parseObjectPath(r2Notification.Object.Key)
	if err != nil {
		logger.Warn("failed to parse object path - message not consumed",
			"messageID", msg.ID,
			"path", r2Notification.Object.Key,
			"error", err,
		)
		return fmt.Errorf("failed to parse object path %q: %w", r2Notification.Object.Key, err)
	}
	parsed.ETag = r2Notification.Object.ETag
	parsed.EventTime = r2Notification.EventTime

	// If TrustCanopy is false, just return (message consumed successfully)
	if !cfg.TrustCanopy {
		return nil
	}

	// TrustCanopy is true - verify hash by reading object
	// Verification failure is logged but message is still consumed (return nil)
	if err := verifyObjectHash(ctx, cfg, parsed, httpClient, logger); err != nil {
		logger.Warn("hash verification failed - message consumed anyway",
			"fenceIndex", parsed.FenceIndex,
			"pathHash", parsed.Hash,
			"error", err,
		)
		// Log error but don't return it - message will be consumed
		return nil
	}

	return nil
}

// parseObjectPath extracts logId, fenceIndex, and hash from R2 object path
// Expected format: logs/{logId}/leaves/{fenceIndex}/{sha256hash}
func parseObjectPath(path string) (*ParsedNotification, error) {
	// Clean path and split
	cleanPath := strings.TrimPrefix(filepath.Clean(path), "/")
	parts := strings.Split(cleanPath, "/")

	// Validate path structure: logs/{logId}/leaves/{fenceIndex}/{hash}
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

	// Validate hash format (should be 64 hex characters for SHA256)
	if len(hash) != 64 {
		return nil, fmt.Errorf("invalid hash length: expected 64 hex characters, got %d", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return nil, fmt.Errorf("invalid hash format: not hex-encoded: %w", err)
	}

	// Parse fenceIndex
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

// verifyObjectHash reads the object from R2 and verifies its SHA256 hash matches the path hash
// Uses the shared HTTPClient for connection pooling and reuse
func verifyObjectHash(ctx context.Context, cfg Config, parsed *ParsedNotification, httpClient *HTTPClient, logger *slog.Logger) error {
	if cfg.R2PublicURL == "" {
		return fmt.Errorf("R2_PUBLIC_URL not configured")
	}

	// Build object URL
	objectURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(cfg.R2PublicURL, "/"), parsed.Path)

	// Fetch object using shared HTTP client for connection pooling
	// Note: resp.Body.Close() returns the connection to the pool for reuse (if keep-alive)
	req, err := http.NewRequest("GET", objectURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to fetch object: %w", err)
	}
	defer resp.Body.Close() // Closes response body and returns connection to pool

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch object: status %d", resp.StatusCode)
	}

	// Read object content
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read object content: %w", err)
	}

	// Compute SHA256 hash
	hasher := sha256.New()
	if _, err := hasher.Write(content); err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}
	computedHash := hex.EncodeToString(hasher.Sum(nil))

	// Verify hash matches
	if computedHash != parsed.Hash {
		return fmt.Errorf("hash mismatch: path has %q, computed %q", parsed.Hash, computedHash)
	}

	return nil
}

// samplePrefix returns up to max characters from the provided string so logs remain concise.
func samplePrefix(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max] + "…"
}

// AcknowledgeMessage acknowledges a message to remove it from the queue
func AcknowledgeMessage(ctx context.Context, cfg Config, httpClient *HTTPClient, messageID string) error {
	baseQueueURL := strings.TrimSuffix(cfg.QueueURL, "/")
	ackURL := fmt.Sprintf("%s/messages/ack", baseQueueURL)

	payload := struct {
		AckIDs []string `json:"ack_ids"`
	}{
		AckIDs: []string{messageID},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal ack payload: %w", err)
	}

	req, err := http.NewRequest("POST", ackURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create ack request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.QueueAPIToken)
	req.Header.Set("Content-Type", "application/json")

	// Use HTTPClient.Do which handles connection pooling and errors
	// Note: resp.Body.Close() returns the connection to the pool for reuse (if keep-alive)
	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to acknowledge message: %w", err)
	}
	defer resp.Body.Close() // Closes response body and returns connection to pool

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("ack request failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return nil
}
