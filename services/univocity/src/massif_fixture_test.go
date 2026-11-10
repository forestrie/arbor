package univocity

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log/slog"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/arbor/services/pkgs/publishproof"
	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog/merklelogtest"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
)

const testMassifHeight = 3

// memLogs is an in-memory MMR log bucket that tests append leaves to, the
// way ranger sequences entries.
type memLogs struct {
	t       *testing.T
	factory *merklelog.Factory
	nextIDT map[logid.UUID]uint64
}

func newMemLogs(t *testing.T) *memLogs {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	factory, err := merklelog.NewFactory(merklelogtest.NewMemClient(), testMassifHeight, logger)
	if err != nil {
		t.Fatalf("massif factory: %v", err)
	}
	return &memLogs{t: t, factory: factory, nextIDT: map[logid.UUID]uint64{}}
}

func (l *memLogs) readers() MassifReaders {
	return NewMassifReaders(l.factory, testMassifHeight)
}

// appendLeaf sequences an entry with contentHash into log, under the next
// idtimestamp, and returns the log's MMR size after it.
func (l *memLogs) appendLeaf(log logid.UUID, contentHash [32]byte) uint64 {
	l.t.Helper()
	ctx := l.t.Context()
	store, err := l.readers().Massif(ctx, log)
	if err != nil {
		l.t.Fatalf("open log: %v", err)
	}
	w := store.(*merklelog.Store)
	mc, err := massifs.GetAppendContext(ctx, w, 0, testMassifHeight)
	if err != nil {
		l.t.Fatalf("append context: %v", err)
	}
	l.nextIDT[log] += 1000
	idts := l.nextIDT[log]
	var idtsBe [8]byte
	binary.BigEndian.PutUint64(idtsBe[:], idts)
	leaf := sha256.Sum256(append(idtsBe[:], contentHash[:]...))
	if _, err := mc.AddIndexedEntry(leaf[:]); err != nil {
		l.t.Fatalf("add leaf: %v", err)
	}
	if err := mc.IndexLeaf(idts, contentHash[:]); err != nil {
		l.t.Fatalf("index leaf: %v", err)
	}
	if err := massifs.CommitContext(ctx, w, &mc); err != nil {
		l.t.Fatalf("commit massif: %v", err)
	}
	return mc.RangeCount()
}

// published returns log's on-chain state for a checkpoint of size: the
// accumulator the contract would hold once that checkpoint is published.
func (l *memLogs) published(log logid.UUID, size uint64) publishproof.LogState {
	l.t.Helper()
	store, err := l.readers().Massif(l.t.Context(), log)
	if err != nil {
		l.t.Fatalf("open log: %v", err)
	}
	mc, err := massifs.GetMassifContext(l.t.Context(), store, 0)
	if err != nil {
		l.t.Fatalf("read massif: %v", err)
	}
	peaks, err := mmr.PeakHashes(&mc, size-1)
	if err != nil {
		l.t.Fatalf("peaks: %v", err)
	}
	acc := make([][32]byte, len(peaks))
	for i, p := range peaks {
		copy(acc[i][:], p)
	}
	return publishproof.LogState{Accumulator: acc, Size: size}
}

func contentHashOf(t *testing.T, stmt []byte) [32]byte {
	t.Helper()
	h, err := publishproof.StoredGrantContentHash(stmt)
	if err != nil {
		t.Fatalf("content hash: %v", err)
	}
	return h
}

var _ = massifstorage.LogID(nil)
