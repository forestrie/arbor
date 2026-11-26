package committer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog/merklelogtest"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/google/uuid"
)

// interleavingClient stands in for a second ranger on the same log: once,
// right after a successful write of triggerKey, it runs interleave.
type interleavingClient struct {
	*merklelogtest.MemClient
	triggerKey string
	interleave func()
}

func (c *interleavingClient) PutObject(
	ctx context.Context, key string, data []byte, opts merklelog.PutOptions,
) (merklelog.PutResult, error) {
	result, err := c.MemClient.PutObject(ctx, key, data, opts)
	if err == nil && key == c.triggerKey && c.interleave != nil {
		interleave := c.interleave
		c.interleave = nil
		interleave()
	}
	return result, err
}

func openLogStore(
	t *testing.T, client merklelog.ObjectClient, logID uuid.UUID, massifHeight uint8,
) *merklelog.Store {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	factory, err := merklelog.NewFactory(client, massifHeight, logger)
	if err != nil {
		t.Fatalf("NewFactory: %v", err)
	}
	store, err := factory.NewStore(massifstorage.LogID(logID[:]))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.SelectLog(ctx, massifstorage.LogID(logID[:])); err != nil {
		t.Fatalf("SelectLog: %v", err)
	}
	return store
}

// TestCommitLogGroupFailsWhenAnotherWriterExtendsAcrossRollover: the
// ingress ack is limit-based (row i gets leaf FirstLeafIndex+i, FOR-653),
// so a batch must occupy contiguous leaves. If another ranger creates the
// next massif between this batch's rollover commit and its next append,
// appending after that ranger's leaves would ack every later row onto the
// wrong leaf. The massif write preconditions (FOR-656) only catch this if
// the batch's first write to the new massif is a create, so the batch must
// fail rather than interleave.
func TestCommitLogGroupFailsWhenAnotherWriterExtendsAcrossRollover(t *testing.T) {
	ctx := context.Background()
	mem := merklelogtest.NewMemClient()
	client := &interleavingClient{MemClient: mem}
	c := newTestCommitter(t, client) // 4 leaves per massif
	logID := uuid.New()

	all := testEntries(5)
	if _, err := c.CommitLogGroup(ctx, logID[:], all[:3]); err != nil {
		t.Fatalf("seed CommitLogGroup: %v", err)
	}
	// The next batch fills massif 0 with its first entry and rolls over on
	// its second. The other writer runs right after massif 0 is written.
	massif0Key, err := openLogStore(t, mem, logID, c.massifHeight).
		ObjectPath(0, massifstorage.ObjectMassifData)
	if err != nil {
		t.Fatalf("ObjectPath: %v", err)
	}
	leafB := sha256.Sum256([]byte("writer B leaf"))
	client.triggerKey = massif0Key
	client.interleave = func() {
		storeB := openLogStore(t, mem, logID, c.massifHeight)
		mcB, err := massifs.GetAppendContext(ctx, storeB, 1, c.massifHeight)
		if err != nil {
			t.Fatalf("B GetAppendContext: %v", err)
		}
		if !mcB.Creating || mcB.Start.MassifIndex != 1 {
			t.Fatalf("B is not creating massif 1 (creating=%v, massif %d)",
				mcB.Creating, mcB.Start.MassifIndex)
		}
		if _, err := mcB.AddIndexedEntry(leafB[:]); err != nil {
			t.Fatalf("B AddIndexedEntry: %v", err)
		}
		// A real second ranger mints above massif 0's last idtimestamp, but
		// when its clock lags this one's its key can still sort below the
		// idtimestamp the batch minted before the rollover. The trie orders
		// keys within one massif only, so reusing massif 0's last key pins
		// that case without depending on clocks.
		key := mcB.Start.LastID
		contentB := sha256.Sum256([]byte("writer B content"))
		if err := mcB.IndexLeaf(key, contentB[:]); err != nil {
			t.Fatalf("B IndexLeaf: %v", err)
		}
		mcB.SetLastIDTimestamp(key)
		if err := massifs.CommitContext(ctx, storeB, &mcB); err != nil {
			t.Fatalf("B CommitContext: %v", err)
		}
	}

	batch := all[3:]
	result, err := c.CommitLogGroup(ctx, logID[:], batch)
	if client.interleave != nil {
		t.Fatal("the other writer never ran: the batch did not roll over")
	}
	if err == nil {
		t.Fatalf("CommitLogGroup succeeded across another writer's massif: "+
			"rows acked from leaf %d onto non-contiguous leaves", result.FirstLeafIndex)
	}
	if result != nil {
		t.Errorf("result = %+v on failure, want nil (a non-nil result could be acked)", result)
	}

	// The other writer's massif is intact, and redelivering the batch
	// appends it contiguously after that writer's leaf.
	mc1, err := massifs.GetMassifContext(ctx, openLogStore(t, mem, logID, c.massifHeight), 1)
	if err != nil {
		t.Fatalf("read massif 1: %v", err)
	}
	if got, err := mc1.Get(mc1.Start.FirstIndex); err != nil || !bytes.Equal(got, leafB[:]) {
		t.Fatalf("massif 1 first leaf = %x (err %v), want the other writer's %x", got, err, leafB)
	}
	result, err = c.CommitLogGroup(ctx, logID[:], batch)
	if err != nil {
		t.Fatalf("redelivered CommitLogGroup: %v", err)
	}
	// Leaves 0-2 seed, 3 the unreferenced copy of batch[0], 4 writer B.
	if result.FirstLeafIndex != 5 || result.Committed != len(batch) {
		t.Errorf("redelivery = %+v, want %d rows from leaf 5", result, len(batch))
	}
}
