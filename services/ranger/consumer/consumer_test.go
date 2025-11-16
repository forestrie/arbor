package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/forestrie/arbor/services/ranger"
)

func TestProcessMessageDecodesBase64Body(t *testing.T) {
	notification := R2Notification{
		Account:   "account",
		Action:    "PutObject",
		Bucket:    "canopy-dev-1-leaves",
		EventTime: "2025-11-09T14:14:52.423Z",
		Object: R2Object{
			Key:  "logs/de305d54-75b4-431b-adb2-eb6b9e546014/leaves/0/" + strings.Repeat("a", 64),
			Size: 53,
			ETag: "etag",
		},
	}

	body, err := json.Marshal(notification)
	if err != nil {
		t.Fatalf("marshal notification: %v", err)
	}

	bodyStringJSON, err := json.Marshal(string(body))
	if err != nil {
		t.Fatalf("wrap notification: %v", err)
	}

	raw := json.RawMessage(bodyStringJSON)

	msg := QueueMessage{
		ID:   "message-id",
		Body: raw,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	consumer := NewQueueConsumer(ranger.Config{TrustCanopy: false}, nil, logger, nil)

	if err := consumer.ProcessMessage(context.Background(), msg); err != nil {
		t.Fatalf("ProcessMessage returned error: %v", err)
	}
}

func TestQueuePullResponseUnmarshal(t *testing.T) {
	r2 := R2Notification{
		Account:   "account",
		Action:    "PutObject",
		Bucket:    "bucket",
		EventTime: "2025-11-09T17:39:43Z",
		Object: R2Object{
			Key:  "logs/de305d54-75b4-431b-adb2-eb6b9e546014/leaves/0/" + strings.Repeat("b", 64),
			Size: 99,
			ETag: "etag",
		},
	}
	rawNotification, err := json.Marshal(r2)
	if err != nil {
		t.Fatalf("marshal notification: %v", err)
	}

	bodyLiteral := strconv.Quote(string(rawNotification))
	payload := fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"message_backlog_count":1,"messages":[{"id":"msg-1","timestamp_ms":1762709980263,"body":%s,"attempts":2}]}}`, bodyLiteral)

	var resp QueuePullResponse
	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		t.Fatalf("unmarshal pull response: %v", err)
	}

	if resp.Result.MessageBacklogCount != 1 {
		t.Fatalf("expected backlog 1, got %d", resp.Result.MessageBacklogCount)
	}
	if len(resp.Result.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Result.Messages))
	}

	msg := resp.Result.Messages[0]
	if msg.ID != "msg-1" {
		t.Fatalf("unexpected message ID %q", msg.ID)
	}
	if msg.Attempts != 2 {
		t.Fatalf("expected attempts 2, got %d", msg.Attempts)
	}

	var bodyString string
	if err := json.Unmarshal(msg.Body, &bodyString); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}

	var parsed R2Notification
	if err := json.Unmarshal([]byte(bodyString), &parsed); err != nil {
		t.Fatalf("parse notification: %v", err)
	}

	if parsed.Object.Key != r2.Object.Key {
		t.Fatalf("expected key %q, got %q", r2.Object.Key, parsed.Object.Key)
	}
}
