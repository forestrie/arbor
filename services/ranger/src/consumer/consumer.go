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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/forestrie/arbor/services/ranger"
	"github.com/google/uuid"
)

// MessageAcker is a function type that acknowledges a queue message.
// It allows the queue consumer to pass in its AcknowledgeMessage function.
type MessageAcker func(ctx context.Context, msg QueueMessage) error

// MassifCommitter provides batch processing of messages into the merklelog.
// This interface is defined in the consumer package to avoid import cycles.
// The committer package implements this interface.
type MassifCommitter interface {
	// ProcessBatch processes messages contained in qbatch.ByLogID[start:end].
	// The caller guarantees the range contains exactly one log's messages.
	// The implementation guarantees to return the index of the last successfully
	// committed batch item.
	// The implementation guarantes that all items after the returned index have
	// not been processed and so should not be acknowleged
	// The implementation may decide to consume errors it considers non transient
	// by  continuing processing (it must record the err in Errs)
	ProcessBatch(ctx context.Context, batch *QueuePullResult, start, end int) (int, error)
}

// QueueConsumer coordinates Cloudflare Queue message consumption.
type QueueConsumer struct {
	cfg        ranger.Config
	httpClient *ranger.HTTPClient
	logger     *slog.Logger
	committer  MassifCommitter // Optional committer for batch processing
}

// NewQueueConsumer constructs a QueueConsumer with a config copy and shared HTTP client.
// If committer is provided, it will be used for batch processing messages into the merklelog.
func NewQueueConsumer(cfg ranger.Config, httpClient *ranger.HTTPClient, logger *slog.Logger, committer MassifCommitter) *QueueConsumer {
	return &QueueConsumer{
		cfg:        cfg,
		httpClient: httpClient,
		logger:     logger,
		committer:  committer,
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
	return q.ProcessBatchWithCommitter(ctx, &queueResp.Result)
}

// AcknowledgeMessage acknowledges a message to remove it from the queue.
func (q *QueueConsumer) AcknowledgeMessage(ctx context.Context, message QueueMessage) error {
	// Primarily for tests: allow suppressing acknowledgements so we don't make
	// external HTTP calls when exercising consumer logic.
	if q.cfg.SuppressAcknowledge {
		return nil
	}

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

// ProcessBatchWithCommitter processes messages using the committer for batch processing.
// It parses messages, sorts them by object key (which groups by logID), and passes them to the committer.
// This is primarily intended for integration tests and internal use; typical callers should
// invoke PullAndProcessMessages which in turn delegates to this method when a committer is configured.
func (q *QueueConsumer) ProcessBatchWithCommitter(ctx context.Context, qbatch *QueuePullResult) error {
	n := len(qbatch.Messages)
	if n == 0 {
		q.logger.Debug("no messages to process")
		return nil
	}

	qbatch.R2Notification = make([]R2Notification, n)
	qbatch.Decoded = make([]ProcessedNotification, n)
	qbatch.Errs = make([]error, n)
	qbatch.Ack = make([]bool, n)
	qbatch.ByLogID = make([]int, n)

	for i, msg := range qbatch.Messages {
		qbatch.ByLogID[i] = i
		var bodyJSON string
		if err := json.Unmarshal(msg.Body, &bodyJSON); err != nil {
			qbatch.Errs[i] = fmt.Errorf("failed unmarshaling body for message id=%s: %w", msg.ID, err)
			qbatch.Ack[i] = true
			continue
		}

		if err := json.Unmarshal([]byte(bodyJSON), &qbatch.R2Notification[i]); err != nil {
			qbatch.Errs[i] = fmt.Errorf("failed parsing R2 notification for message id=%s: %w", msg.ID, err)
			qbatch.Ack[i] = true
			continue
		}

		if qbatch.R2Notification[i].Action != "PutObject" {
			qbatch.Errs[i] = fmt.Errorf("unexpected notification %s for message id=%s", qbatch.R2Notification[i].Action, msg.ID)
			qbatch.Ack[i] = true
			continue
		}

		if err := processObjectPath(&qbatch.Decoded[i], qbatch.R2Notification[i].Object.Key); err != nil {
			qbatch.Errs[i] = fmt.Errorf("failed to parse object path %s for message id=%s: %w", qbatch.R2Notification[i].Object.Key, msg.ID, err)
			qbatch.Ack[i] = true
			continue
		}

		qbatch.Decoded[i].ETag = qbatch.R2Notification[i].Object.ETag
		qbatch.Decoded[i].EventTime = qbatch.R2Notification[i].EventTime
	}

	sort.SliceStable(qbatch.ByLogID, func(i, j int) bool {
		li := qbatch.ByLogID[i]
		lj := qbatch.ByLogID[j]

		liErr := qbatch.Errs[li]
		ljErr := qbatch.Errs[lj]

		if liErr == nil && ljErr != nil {
			return true
		}
		if liErr != nil && ljErr == nil {
			return false
		}
		if liErr != nil && ljErr != nil {
			return li < lj
		}

		if cmp := bytes.Compare(qbatch.Decoded[li].LogID, qbatch.Decoded[lj].LogID); cmp != 0 {
			return cmp < 0
		}
		return qbatch.Decoded[li].FenceIndex < qbatch.Decoded[lj].FenceIndex
	})

	var (
		wg                  sync.WaitGroup
		errorStart          = len(qbatch.ByLogID)
		processedAtLeastOne = false
	)

	numMsgs := len(qbatch.ByLogID)
	for start := 0; start < numMsgs; {
		startIdx := qbatch.ByLogID[start]
		if qbatch.Errs[startIdx] != nil {
			errorStart = start
			break
		}

		end := start + 1
		for end < numMsgs {
			nextIdx := qbatch.ByLogID[end]
			if qbatch.Errs[nextIdx] != nil {
				errorStart = end
				break
			}
			if bytes.Equal(qbatch.Decoded[nextIdx].LogID, qbatch.Decoded[startIdx].LogID) {
				end++
				continue
			}
			break
		}

		wg.Add(1)
		processedAtLeastOne = true
		go func(start, end int) {
			defer wg.Done()
			lastCommit, err := q.committer.ProcessBatch(ctx, qbatch, start, end)
			if err != nil {
				logID := hex.EncodeToString(qbatch.Decoded[qbatch.ByLogID[start]].LogID)
				q.logger.Error("failed to process log batch",
					"logID", logID,
					"start", start,
					"end", end,
					"lastCommit", lastCommit,
					"error", err,
				)
				if lastCommit > start {
					q.ackBatch(ctx, qbatch, start, lastCommit)
				}
				return
			}
			// After ProcessBatch, acknowledge all messages in the consumed range
			// [start,lastCommit). Items at or after lastCommit are left unacked to
			// become available again once their visibility timeout expires.
			q.ackBatch(ctx, qbatch, start, lastCommit)
		}(start, end)

		start = end
		if errorStart < numMsgs {
			break
		}
	}

	wg.Wait()

	if errorStart < len(qbatch.ByLogID) {
		q.ackBatch(ctx, qbatch, errorStart, len(qbatch.ByLogID))
	}

	if !processedAtLeastOne {
		q.logger.Debug("no valid messages to process")
	}

	// Return nil - all errors are logged, and we successfully attempted processing
	return nil
}

func (q *QueueConsumer) ackBatch(ctx context.Context, qbatch *QueuePullResult, start, end int) {
	var wg sync.WaitGroup

	// end marks the end of a sub batch for a single log id, or marks the last
	// consumed message in that batch. consumed means committed to the log or
	// determinted to be not re-tryable
	//
	for i := start; i < end; i++ {

		msgIdx := qbatch.ByLogID[i]

		// NOTICE: If ProcessBatch stopped part way through a batch due to an
		// error, messages from that point will not be acknowledged here because
		// ack will be false.

		wg.Add(1)
		go func(msgIdx int) {
			defer wg.Done()
			if err := q.AcknowledgeMessage(ctx, qbatch.Messages[msgIdx]); err != nil {
				q.logger.Warn("failed to acknowledge message",
					"messageID", qbatch.Messages[msgIdx].ID,
					"error", err,
				)
			}
			if qbatch.Errs[msgIdx] != nil {
				q.logger.Warn("message processing", "err", qbatch.Errs[msgIdx])
			}
		}(msgIdx)
	}

	wg.Wait()

	q.logger.Info("ackBatch", "acked", end-start)
}

// processObjectPath extracts logId, fenceIndex, and hash from R2 object path.
func processObjectPath(note *ProcessedNotification, path string) error {
	var err error

	cleanPath := strings.TrimPrefix(filepath.Clean(path), "/")
	note.Path = cleanPath
	parts := strings.Split(cleanPath, "/")

	if len(parts) < 5 {
		return fmt.Errorf("invalid path format: expected logs/{logId}/leaves/{fenceIndex}/{hash}, got %d segments", len(parts))
	}

	if parts[0] != "logs" {
		return fmt.Errorf("invalid path format: expected 'logs' prefix, got %q", parts[0])
	}
	if parts[2] != "leaves" {
		return fmt.Errorf("invalid path format: expected 'leaves' segment, got %q", parts[2])
	}

	uid, err := uuid.Parse(parts[1])
	if err != nil {
		return err
	}
	note.LogID = uid[:]

	// fenceIndexStr := parts[3]
	hash := parts[4]

	if len(hash) != 64 {
		return fmt.Errorf("invalid hash length: expected 64 hex characters, got %d", len(hash))
	}
	if note.Hash, err = hex.DecodeString(hash); err != nil {
		return fmt.Errorf("invalid hash format: not hex-encoded: %w", err)
	}

	// i, err := strconv.ParseInt(fenceIndexStr, 10, 64)
	// if err != nil {
	// 	return fmt.Errorf("invalid fenceIndex %q: %w", fenceIndexStr, err)
	// }
	// note.FenceIndex = uint64(i)

	// Compute extraBytes0 and extraBytes1 to match TypeScript encoding:
	// extraBytes0 = 32 bytes: 16 bytes zeros + 8 bytes (fenceIndex as big-endian uint64)
	// extraBytes1 = 32 bytes (full hash)
	copy(note.ExtraBytes0, note.Hash)

	return nil
}

func samplePrefix(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max] + "…"
}
