package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"testing"
)

// checkpointMsg builds a queue message carrying an R2 PutObject notification for
// a checkpoint key, matching the double-wrapped body the consumer decodes.
func checkpointMsg(t *testing.T, id, key string) QueueMessage {
	t.Helper()
	inner, err := json.Marshal(R2Notification{Action: "PutObject", Object: R2Object{Key: key}})
	if err != nil {
		t.Fatalf("marshal notification: %v", err)
	}
	body, err := json.Marshal(string(inner)) // the queue wraps the body as a JSON string
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return QueueMessage{ID: id, Body: body, LeaseID: "lease-" + id}
}

func ckKey(uuid string, massif int) string {
	return fmt.Sprintf("v2/merklelog/checkpoints/14/%s/%016d.sth", uuid, massif)
}

func TestCoalesceByLogKeepsHighestMassif(t *testing.T) {
	q := &QueueConsumer{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	const logA = "70717273-7475-4677-a879-7a7b7c7d7e7f"
	const logB = "60616263-6465-4667-a869-6a6b6c6d6e6f"

	msgs := []QueueMessage{
		checkpointMsg(t, "a1", ckKey(logA, 1)),
		checkpointMsg(t, "a0", ckKey(logA, 0)),
		checkpointMsg(t, "a2", ckKey(logA, 2)), // highest for logA
		checkpointMsg(t, "b5", ckKey(logB, 5)), // only one for logB
	}

	groups := q.coalesce(context.Background(), msgs)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (one per log)", len(groups))
	}

	byPrimary := map[string]logGroup{}
	for _, g := range groups {
		byPrimary[g.primary.ID] = g
	}
	a, ok := byPrimary["a2"]
	if !ok {
		t.Fatalf("logA primary should be the highest massif (a2); groups=%v", byPrimary)
	}
	if a.massif != 2 {
		t.Errorf("logA primary massif = %d, want 2", a.massif)
	}
	if len(a.siblings) != 2 {
		t.Errorf("logA siblings = %d, want 2 (a0, a1 subsumed)", len(a.siblings))
	}
	b, ok := byPrimary["b5"]
	if !ok || len(b.siblings) != 0 {
		t.Errorf("logB should be a lone primary with no siblings, got ok=%v siblings=%d", ok, len(b.siblings))
	}
}
