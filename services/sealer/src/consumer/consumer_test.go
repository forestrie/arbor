package consumer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/google/uuid"
)

func TestQueuePullResponseUnmarshal(t *testing.T) {
	r2 := R2Notification{
		Account:   "account",
		Action:    "PutObject",
		Bucket:    "bucket",
		EventTime: "2025-11-09T17:39:43Z",
		Object: R2Object{
			Key:  "v2/merklelog/massifs/14/de305d54-75b4-431b-adb2-eb6b9e546014/0000000000000000.log",
			Size: 99,
			ETag: "etag",
		},
	}
	rawNotification, err := json.Marshal(r2)
	if err != nil {
		t.Fatalf("marshal notification: %v", err)
	}

	bodyLiteral := strconv.Quote(string(rawNotification))
	payload := fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"message_backlog_count":1,"messages":[{"id":"msg-1","timestamp_ms":1762709980263,"body":%s,"attempts":2,"lease_id":"lease-1"}]}}`, bodyLiteral)

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
	if msg.LeaseID != "lease-1" {
		t.Fatalf("expected lease ID %q, got %q", "lease-1", msg.LeaseID)
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

func TestParseLogIDFromObjectPath(t *testing.T) {
	logID := uuid.New()
	key := fmt.Sprintf("v2/merklelog/massifs/14/%s/0000000000000000.log", logID.String())

	b, err := parseLogIDFromObjectPath(key)
	if err != nil {
		t.Fatalf("parseLogIDFromObjectPath: %v", err)
	}

	roundTrip, err := uuid.FromBytes(b)
	if err != nil {
		t.Fatalf("uuid.FromBytes: %v", err)
	}

	if roundTrip != logID {
		t.Fatalf("expected %s, got %s", logID, roundTrip)
	}
}
