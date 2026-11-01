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

// TestCommitLogGroupBadHashFailsWholeBatch is the FOR-653 acceptance: one bad
// content hash fails the batch with nothing written. The forestrie-ingress
// ack is limit-based, so skipping the entry and acking the rest would put
// every later row on the wrong leaf. The bad entry sits past the first
// massif's capacity, so a committer that checked it in the write loop would
// already have written massif 0 by the time it failed.
func TestCommitLogGroupBadHashFailsWholeBatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := merklelogtest.NewMemClient()

	const massifHeight = 3 // 4 leaves per massif, so 10 entries roll over
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
	c := &Committer{
		factory:         factory,
		idState:         idState,
		logger:          logger,
		massifHeight:    massifHeight,
		commitmentEpoch: 1,
	}

	entries := make([]ingress.Entry, 10)
	for i := range entries {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		h := sha256.Sum256(b[:])
		entries[i] = ingress.Entry{ContentHash: h[:]}
	}
	const bad = 7
	entries[bad].ContentHash = entries[bad].ContentHash[:31]

	logID := uuid.New()
	result, err := c.CommitLogGroup(context.Background(), logID[:], entries)
	if err == nil {
		t.Fatalf("CommitLogGroup succeeded with a 31-byte content hash at entry %d", bad)
	}
	if result != nil && result.Committed != 0 {
		t.Errorf("Committed = %d on failure, want 0 (a non-zero count would be acked)", result.Committed)
	}
	if keys := client.Keys(); len(keys) != 0 {
		t.Errorf("failed batch wrote %d objects, want none: %v", len(keys), keys)
	}
}
