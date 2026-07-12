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
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/google/uuid"
)

// TestCommitLogGroupRecordsMassifObjectKeys is the plan-2607-03 R3 acceptance:
// CommitResult.MassifObjectKeys carries exactly the object paths of the
// massifs this commit wrote — contiguous indexes from 0, in write order, no
// drops or duplicates — across at least one massif rollover. A wrong key here
// would aim seal hints (ADR-0007 phase 1) at nonexistent objects and silently
// zero the ranger_hint wake path.
func TestCommitLogGroupRecordsMassifObjectKeys(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := merklelogtest.NewMemClient()

	const massifHeight = 3 // small massifs so a modest batch rolls over
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

	logID := uuid.New()
	entries := make([]ingress.Entry, 10)
	for i := range entries {
		h := sha256.New()
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		h.Write(b[:])
		entries[i] = ingress.Entry{ContentHash: h.Sum(nil)}
	}

	result, err := c.CommitLogGroup(context.Background(), logID[:], entries)
	if err != nil {
		t.Fatalf("CommitLogGroup: %v", err)
	}
	if result.Committed != len(entries) {
		t.Fatalf("committed = %d, want %d", result.Committed, len(entries))
	}

	if len(result.MassifObjectKeys) < 2 {
		t.Fatalf("MassifObjectKeys = %v — rollover not exercised (need >= 2 massifs); shrink massifHeight or add entries", result.MassifObjectKeys)
	}

	// Expected keys: contiguous massif indexes from 0, in write order, computed
	// by the same store the committer used.
	store, err := factory.NewStore(massifstorage.LogID(logID[:]))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.SelectLog(context.Background(), massifstorage.LogID(logID[:])); err != nil {
		t.Fatalf("SelectLog: %v", err)
	}
	for i, got := range result.MassifObjectKeys {
		want, err := store.ObjectPath(uint32(i), massifstorage.ObjectMassifData)
		if err != nil {
			t.Fatalf("ObjectPath(%d): %v", i, err)
		}
		if got != want {
			t.Errorf("MassifObjectKeys[%d] = %q, want %q (drop/duplicate/wrong index)", i, got, want)
		}
	}

	// Every recorded key must exist in storage — a hint must reference a
	// massif object the sealer can actually read.
	stored := map[string]bool{}
	for _, k := range client.Keys() {
		stored[k] = true
	}
	for _, k := range result.MassifObjectKeys {
		if !stored[k] {
			t.Errorf("recorded key %q was never written to storage", k)
		}
	}
}
