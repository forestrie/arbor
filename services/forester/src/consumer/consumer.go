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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/forestrie/arbor/services/forester"
	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/forestrie/go-merklelog/urkle"
)

// QueueConsumer coordinates Cloudflare Queue message consumption.
type QueueConsumer struct {
	cfg        forester.Config
	httpClient *forester.HTTPClient
	logger     *slog.Logger
}

type kvBulkEntry struct {
	Key           string `json:"key"`
	Value         string `json:"value"`
	ExpirationTTL *int   `json:"expiration_ttl,omitempty"`
}

// receiptCacheEntryV1 is the in-memory representation of a KV cache value
// for ranger/v1/{logId}/latest/{contentHash}.
//
// Note: we keep numeric types here for easy comparison (latest-wins), but we
// serialize uint64 values as decimal strings when writing to KV to avoid
// consumers accidentally parsing them as IEEE-754 numbers.
type receiptCacheEntryV1 struct {
	MassifHeight uint8
	MMRIndex     uint64
	IDTimestamp  uint64
}

// receiptCacheValueV1 is the on-wire KV JSON schema written by Forester.
type receiptCacheValueV1 struct {
	V            int    `json:"v"`
	MassifHeight uint8  `json:"massifHeight"`
	MMRIndex     string `json:"mmrIndex"`
	IDTimestamp  string `json:"idtimestamp"`
}

// NewQueueConsumer constructs a QueueConsumer with a config copy and shared HTTP client.
func NewQueueConsumer(cfg forester.Config, httpClient *forester.HTTPClient, logger *slog.Logger) *QueueConsumer {
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

// PullAndProcessMessages pulls messages from the queue, decodes R2 notifications, logs them,
// and acknowledges messages regardless of decode/parsing errors.
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

	req.Header.Set("Authorization", "Bearer "+q.cfg.QueueToken)
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

	q.ProcessAndAcknowledge(ctx, &queueResp.Result)
	return nil
}

// ProcessAndAcknowledge decodes notifications and acknowledges all messages.
// The goal is to avoid poisoning the queue even if a message is malformed.
func (q *QueueConsumer) ProcessAndAcknowledge(ctx context.Context, qbatch *QueuePullResult) {
	// Collect receipt cache updates for any massif notifications in this batch.
	//
	// We intentionally implement "latest registration wins" for a content hash by
	// always writing the most recent idtimestamp value for a given contentHash key.
	// This matches Forestrie's design: content-hash is a transient SCRAPI id that
	// may be reused after ingress expiry.
	receiptMax := make(map[string]receiptCacheEntryV1)

	for _, msg := range qbatch.Messages {
		note, ok := decodeR2Notification(q.logger, msg)
		if ok && note.Action == "PutObject" {
			q.logger.Info("decoded R2 notification",
				"messageID", msg.ID,
				"attempts", msg.Attempts,
				"account", note.Account,
				"bucket", note.Bucket,
				"key", note.Object.Key,
				"size", note.Object.Size,
				"eTag", note.Object.ETag,
				"eventTime", note.EventTime,
			)

			// If this is a massif data object update, scan its Urkle leaf table and
			// derive receipt cache entries:
			//   ranger/v1/{logId}/latest/{contentHashHex} -> {massifHeight,mmrIndex,idtimestamp}.
			if err := q.collectReceiptsFromMassif(ctx, note.Object.Key, receiptMax); err != nil {
				q.logger.Error("failed to collect receipts from massif",
					"key", note.Object.Key,
					"error", err,
				)
			}
		} else if ok {
			q.logger.Debug("skipping non-PutObject notification",
				"messageID", msg.ID,
				"action", note.Action,
				"bucket", note.Bucket,
				"key", note.Object.Key,
			)
		}
	}

	// Bulk write any derived receipt mappings.
	if len(receiptMax) > 0 {
		if err := q.bulkWriteReceiptCache(ctx, receiptMax); err != nil {
			q.logger.Error("failed to bulk write receipt cache", "error", err)
		} else {
			q.logger.Info("wrote receipt cache entries", "count", len(receiptMax))
		}
	}

	q.ackAll(ctx, qbatch.Messages)
}

func decodeR2Notification(logger *slog.Logger, msg QueueMessage) (R2Notification, bool) {
	var bodyJSON string
	if err := json.Unmarshal(msg.Body, &bodyJSON); err != nil {
		logger.Warn("failed to unmarshal message body wrapper", "messageID", msg.ID, "error", err)
		return R2Notification{}, false
	}

	var note R2Notification
	if err := json.Unmarshal([]byte(bodyJSON), &note); err != nil {
		logger.Warn("failed to unmarshal R2 notification", "messageID", msg.ID, "error", err)
		return R2Notification{}, false
	}

	return note, true
}

func (q *QueueConsumer) isMassifDataObjectKey(key string) bool {
	_, _, _, ok, err := parseV2MassifDataObjectKey(key)
	return ok && err == nil
}

func (q *QueueConsumer) collectReceiptsFromMassif(ctx context.Context, objectKey string, out map[string]receiptCacheEntryV1) error {
	massifHeight, logID, massifIndex, ok, err := parseV2MassifDataObjectKey(objectKey)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	// Build an object reader for this massifHeight.
	factory, err := merklelog.NewS3FactoryWithCredentials(
		q.cfg.R2URL,
		"", // no bearer token; Forester uses AWS credentials for authenticated reads
		q.cfg.AWSAccessKeyID,
		q.cfg.AWSSecretAccessKey,
		q.cfg.AWSRegion,
		massifHeight,
		q.httpClient,
		q.logger,
		s3.WithContentSHA256(true),
	)
	if err != nil {
		return fmt.Errorf("build s3 factory: %w", err)
	}
	store, err := factory.NewStore(logID)
	if err != nil {
		return fmt.Errorf("build store: %w", err)
	}

	mc, err := massifs.GetMassifContext(ctx, store, massifIndex)
	if err != nil {
		return fmt.Errorf("read massif context: %w", err)
	}
	leafTable, err := mc.UrkleLeafTableRegion()
	if err != nil {
		return fmt.Errorf("read urkle leaf table: %w", err)
	}

	leafCount := mc.MassifLeafCount()
	if leafCount > uint64(^uint32(0)) {
		return fmt.Errorf("leafCount too large: %d", leafCount)
	}

	// Derive the global leaf index for each ordinal in this massif.
	// For massifHeight H (1..64), each massif contains 2^(H-1) leaves.
	if massifHeight == 0 || massifHeight > 64 {
		return fmt.Errorf("invalid massifHeight %d (expected 1..64)", massifHeight)
	}
	leavesPerMassif := uint64(1) << (massifHeight - 1)
	if leafCount > leavesPerMassif {
		return fmt.Errorf(
			"leafCount too large for massifHeight: leafCount=%d leavesPerMassif=%d height=%d",
			leafCount,
			leavesPerMassif,
			massifHeight,
		)
	}

	mi := uint64(massifIndex)
	if mi > 0 && leavesPerMassif > ^uint64(0)/mi {
		return fmt.Errorf(
			"leafIndex overflow computing base: leavesPerMassif=%d massifIndex=%d",
			leavesPerMassif,
			massifIndex,
		)
	}
	baseLeafIndex := leavesPerMassif * mi

	for ord := uint32(0); ord < uint32(leafCount); ord++ {
		idts := urkle.LeafKey(leafTable, ord)
		val := urkle.LeafValue(leafTable, ord)
		contentHex := hex.EncodeToString(val[:])
		cacheKey, err := receiptCacheKeyV1(logID, contentHex)
		if err != nil {
			return err
		}

		// Compute mmrIndex from the massif/chunk context + leaf ordinal.
		leafOrd := uint64(ord)
		if baseLeafIndex > ^uint64(0)-leafOrd {
			return fmt.Errorf("leafIndex overflow: base=%d ord=%d", baseLeafIndex, ord)
		}
		leafIndex := baseLeafIndex + leafOrd
		mmrIndex := mmr.MMRIndex(leafIndex)

		entry := receiptCacheEntryV1{
			MassifHeight: massifHeight,
			MMRIndex:     mmrIndex,
			IDTimestamp:  idts,
		}

		// Keep the maximum idtimestamp per content hash (latest wins).
		if prev, ok := out[cacheKey]; !ok || idts > prev.IDTimestamp {
			out[cacheKey] = entry
		}
	}

	return nil
}

func (q *QueueConsumer) bulkWriteReceiptCache(ctx context.Context, entries map[string]receiptCacheEntryV1) error {
	ttl := q.cfg.ReceiptKVExpirationTTLSeconds
	var ttlPtr *int
	if ttl > 0 {
		ttlPtr = &ttl
	}

	// Flatten map -> slice.
	payload := make([]kvBulkEntry, 0, len(entries))
	for k, e := range entries {
		value := receiptCacheValueV1{
			V:            1,
			MassifHeight: e.MassifHeight,
			MMRIndex:     strconv.FormatUint(e.MMRIndex, 10),
			IDTimestamp:  fmt.Sprintf("0x%x", e.IDTimestamp),
		}
		b, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("marshal receipt cache value for key %q: %w", k, err)
		}

		payload = append(payload, kvBulkEntry{
			Key:           k,
			Value:         string(b),
			ExpirationTTL: ttlPtr,
		})
	}

	// Cloudflare bulk API has request size limits; use conservative chunking.
	const chunkSize = 5000
	for i := 0; i < len(payload); i += chunkSize {
		j := i + chunkSize
		if j > len(payload) {
			j = len(payload)
		}
		if err := q.putKVBatch(ctx, payload[i:j]); err != nil {
			return err
		}
	}

	return nil
}

func (q *QueueConsumer) putKVBatch(ctx context.Context, entries []kvBulkEntry) error {
	url := fmt.Sprintf(
		"https://api.cloudflare.com/client/v4/accounts/%s/storage/kv/namespaces/%s/bulk",
		q.cfg.CloudflareAccountID,
		q.cfg.RangerMMRIndexNamespaceID,
	)

	body, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal kv entries: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build kv request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+q.cfg.KVToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := q.httpClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("kv bulk write request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("kv bulk write failed: status=%d body=%s", resp.StatusCode, string(respBytes))
	}

	// Best-effort parse Cloudflare API response success flag.
	var parsed struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err == nil {
		if !parsed.Success {
			return fmt.Errorf("kv bulk write failed: %v", parsed.Errors)
		}
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

	req.Header.Set("Authorization", "Bearer "+q.cfg.QueueToken)
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

	return nil
}

func (q *QueueConsumer) ackAll(ctx context.Context, messages []QueueMessage) {
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)

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
