package committer

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log/slog"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog/merklelogtest"
	"github.com/forestrie/arbor/services/ranger/consumer/ingress"
	"github.com/forestrie/go-merklelog/massifs/snowflakeid"
	"github.com/google/uuid"
)

// newTestCommitter returns a committer over an in-memory store with
// massifHeight 3 (4 leaves per massif), so a 10-entry batch rolls over.
func newTestCommitter(t *testing.T, client *merklelogtest.MemClient) *Committer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	const massifHeight = 3
	factory, err := merklelog.NewFactory(client, massifHeight, logger)
	if err != nil {
		t.Fatalf("NewFactory: %v", err)
	}
	idState, err := snowflakeid.NewIDState(snowflakeid.Config{
		CommitmentEpoch: 1,
		WorkerCIDR:      "10.0.0.0/24",
		PodIP:           "10.0.0.5",
		AllowSpins:      snowflakeid.MaxSpins,
	})
	if err != nil {
		t.Fatalf("NewIDState: %v", err)
	}
	return &Committer{
		factory:         factory,
		idState:         idState,
		logger:          logger,
		massifHeight:    massifHeight,
		commitmentEpoch: 1,
	}
}

// testEntries returns n entries with distinct sha256 content hashes.
func testEntries(n int) []ingress.Entry {
	entries := make([]ingress.Entry, n)
	for i := range entries {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		h := sha256.Sum256(b[:])
		entries[i] = ingress.Entry{ContentHash: h[:]}
	}
	return entries
}

// TestCommitLogGroupBadHashFailsWholeBatch is the FOR-653 acceptance: a bad
// entry fails the batch instead of being skipped. The forestrie-ingress ack
// is limit-based (row i gets leaf firstLeafIndex+i), so skipping the entry
// and acking the rest would put every later row on the wrong leaf. An error
// with a nil result means the consumer does not ack and the batch redelivers.
func TestCommitLogGroupBadHashFailsWholeBatch(t *testing.T) {
	tests := []struct {
		name string
		bad  int
		// massifs written before the failure: a failure after a rollover
		// leaves the full massif in storage, and the redelivery appends the
		// batch again, so those leaves become unreferenced duplicates.
		wantObjects int
	}{
		{name: "before rollover", bad: 2, wantObjects: 0},
		{name: "after rollover", bad: 7, wantObjects: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := merklelogtest.NewMemClient()
			c := newTestCommitter(t, client)

			entries := testEntries(10)
			entries[tt.bad].ContentHash = entries[tt.bad].ContentHash[:31]

			logID := uuid.New()
			result, err := c.CommitLogGroup(context.Background(), logID[:], entries)
			if err == nil {
				t.Fatalf("CommitLogGroup succeeded with a 31-byte content hash at entry %d", tt.bad)
			}
			if result != nil {
				t.Errorf("result = %+v on failure, want nil (a non-nil result could be acked)", result)
			}
			if keys := client.Keys(); len(keys) != tt.wantObjects {
				t.Errorf("wrote %d objects, want %d: %v", len(keys), tt.wantObjects, keys)
			}
		})
	}
}
