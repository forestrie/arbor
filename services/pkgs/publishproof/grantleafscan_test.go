package publishproof

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/forestrie/go-univocity/grant"
	"github.com/stretchr/testify/require"
)

// growingOwnerLog is an owner log that tests extend in steps, the way ranger
// does between publisher polls. Each reader() is a fresh store over the
// committed objects, so it sees exactly what has been committed so far.
type growingOwnerLog struct {
	t       *testing.T
	client  *memObjectClient
	logID   massifstorage.LogID
	height  uint8
	oracle  *memMMR
	size    uint64
	nextIDs uint64
}

func newGrowingOwnerLog(t *testing.T, height uint8) *growingOwnerLog {
	return &growingOwnerLog{
		t:      t,
		client: newMemObjectClient(),
		logID:  mustHex(t, "0102030405060708090a0b0c0d0e0f10"),
		height: height,
		oracle: &memMMR{},
	}
}

func (l *growingOwnerLog) store() *merklelog.Store {
	l.t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	factory, err := merklelog.NewFactory(l.client, l.height, logger)
	require.NoError(l.t, err)
	s, err := factory.NewStore(l.logID)
	require.NoError(l.t, err)
	require.NoError(l.t, s.SelectLog(l.t.Context(), l.logID))
	return s
}

// append commits entries as new leaves, indexed under their idtimestamps.
func (l *growingOwnerLog) append(entries ...fixtureEntry) {
	l.t.Helper()
	ctx := l.t.Context()
	w := l.store()
	mc, err := massifs.GetAppendContext(ctx, w, 0, l.height)
	require.NoError(l.t, err)
	for _, e := range entries {
		leaf := leafCommitment(e)
		_, err = mc.AddIndexedEntry(leaf[:])
		if err == massifs.ErrMassifFull {
			require.NoError(l.t, massifs.CommitContext(ctx, w, &mc))
			w = l.store()
			mc, err = massifs.GetAppendContext(ctx, w, 0, l.height)
			require.NoError(l.t, err)
			_, err = mc.AddIndexedEntry(leaf[:])
		}
		require.NoError(l.t, err)
		require.NoError(l.t, mc.IndexLeaf(e.idts, e.contentHash[:]))
		l.size, err = mmr.AddHashedLeaf(l.oracle, sha256.New(), leaf[:])
		require.NoError(l.t, err)
	}
	require.NoError(l.t, massifs.CommitContext(ctx, w, &mc))
}

func (l *growingOwnerLog) reader() *countingReader {
	return &countingReader{ObjectReader: l.store()}
}

func (l *growingOwnerLog) accumulator() [][32]byte {
	l.t.Helper()
	peaks, err := mmr.PeakHashes(l.oracle, l.size-1)
	require.NoError(l.t, err)
	acc := make([][32]byte, len(peaks))
	for i, p := range peaks {
		copy(acc[i][:], p)
	}
	return acc
}

// countingReader records which massifs are read from the store.
type countingReader struct {
	massifs.ObjectReader
	mu    sync.Mutex
	reads map[uint32]int
	heads int
}

func (r *countingReader) note(i uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.reads == nil {
		r.reads = map[uint32]int{}
	}
	r.reads[i]++
}

func (r *countingReader) MassifData(i uint32) ([]byte, bool, error) {
	r.note(i)
	return r.ObjectReader.MassifData(i)
}

func (r *countingReader) HeadIndex(ctx context.Context, ty massifstorage.ObjectType) (uint32, error) {
	r.mu.Lock()
	r.heads++
	r.mu.Unlock()
	return r.ObjectReader.HeadIndex(ctx, ty)
}

func (r *countingReader) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.heads
	for _, c := range r.reads {
		n += c
	}
	return n
}

func (r *countingReader) readOf(i uint32) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reads[i]
}

func entryN(n uint64) fixtureEntry {
	return fixtureEntry{idts: n * 100, contentHash: sha256.Sum256([]byte{byte(n), 'e'})}
}

func idtsBe(v uint64) [8]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b
}

// scanTestGrant builds a stored grant statement with the given idtimestamp
// header and the content hash ranger would commit for it.
func scanTestGrant(t *testing.T, idts []byte) ([]byte, [32]byte) {
	t.Helper()
	owner := testLogID(t, "10000000-0000-4000-8000-000000000001")
	subject := testLogID(t, "20000000-0000-4000-8000-000000000002")
	grantData := make([]byte, 64)
	grantData[0] = 0xcd
	raw := encodeStoredGrant(t, storedGrantOpts{
		logID: subject, ownerLogID: owner, flags: testFlagsExtendData,
		maxHeight: 1000, minGrowth: 2, grantData: grantData, idts: idts,
	})
	lw, ow := subject.ToPaddedWire32(), owner.ToPaddedWire32()
	want := grant.InnerHash(lw[:], testFlagsExtendData, 1000, 2, ow[:], grantData)
	return raw, want
}

// The scan locates a grant whose idtimestamp the stored statement never
// recorded (header absent, or still the zero placeholder), recovering the
// idtimestamp from the owner log's leaf table.
func TestScanGrantLeafFindsGrantWithoutStoredIDTimestamp(t *testing.T) {
	for name, idts := range map[string][]byte{
		"header absent": nil,
		"header zero":   make([]byte, 8),
	} {
		t.Run(name, func(t *testing.T) {
			raw, want := scanTestGrant(t, idts)
			hash, err := StoredGrantContentHash(raw)
			require.NoError(t, err)
			require.Equal(t, want, hash)

			log := newGrowingOwnerLog(t, fixtureMassifHeight)
			log.append(entryN(1), entryN(2), fixtureEntry{idts: 250, contentHash: hash}, entryN(4))

			gl, found, next, err := ScanGrantLeaf(t.Context(), log.reader(), hash, 0)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, mmr.MMRIndex(2), gl.MMRIndex)
			require.Equal(t, uint64(2), gl.LeafIndex)
			require.Equal(t, idtsBe(250), gl.IDTimestampBe)
			require.Equal(t, leafCommitment(fixtureEntry{idts: 250, contentHash: hash}), gl.Leaf)
			require.Equal(t, uint64(3), next, "next resumes after the match")
		})
	}
}

func TestStoredGrantContentHashRejectsGarbage(t *testing.T) {
	_, err := StoredGrantContentHash([]byte{0xff, 0x00})
	require.Error(t, err)
}

// A miss reports the leaf count as the resume point; a later scan from there
// finds a grant appended since, without reading the massifs it already covered.
func TestScanGrantLeafResumesFromNextWithoutRescanning(t *testing.T) {
	// height 3: 4 leaves per massif.
	log := newGrowingOwnerLog(t, 3)
	late := sha256.Sum256([]byte("late grant"))
	log.append(entryN(1), entryN(2), entryN(3), entryN(4), entryN(5))

	_, found, next, err := ScanGrantLeaf(t.Context(), log.reader(), late, 0)
	require.NoError(t, err)
	require.False(t, found)
	require.Equal(t, uint64(5), next)

	log.append(entryN(6), fixtureEntry{idts: 9000, contentHash: late})
	rd := log.reader()
	gl, found, next2, err := ScanGrantLeaf(t.Context(), rd, late, next)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, uint64(6), gl.LeafIndex)
	require.Equal(t, idtsBe(9000), gl.IDTimestampBe)
	require.Equal(t, uint64(7), next2)
	require.Zero(t, rd.readOf(0), "massif 0 holds only leaves before the cursor")
}

func TestScanGrantLeafMissAtCursorReturnsCursor(t *testing.T) {
	log := newGrowingOwnerLog(t, 3)
	log.append(entryN(1), entryN(2), entryN(3))
	_, found, next, err := ScanGrantLeaf(t.Context(), log.reader(), sha256.Sum256([]byte("x")), 3)
	require.NoError(t, err)
	require.False(t, found)
	require.Equal(t, uint64(3), next)
}

func TestScanGrantLeafEmptyOwnerLog(t *testing.T) {
	log := newGrowingOwnerLog(t, 3)
	_, found, next, err := ScanGrantLeaf(t.Context(), log.reader(), [32]byte{1}, 0)
	require.NoError(t, err)
	require.False(t, found)
	require.Equal(t, uint64(0), next)
}

// The matching leaf may live in a later massif; its global indices account for
// the massifs before it.
func TestScanGrantLeafInLaterMassif(t *testing.T) {
	log := newGrowingOwnerLog(t, 3) // 4 leaves per massif
	target := fixtureEntry{idts: 555, contentHash: sha256.Sum256([]byte("target"))}
	log.append(entryN(1), entryN(2), entryN(3), entryN(4), entryN(5), target, entryN(7))

	rd := log.reader()
	head, err := rd.HeadIndex(t.Context(), massifstorage.ObjectMassifData)
	require.NoError(t, err)
	require.Equal(t, uint32(1), head)

	gl, found, next, err := ScanGrantLeaf(t.Context(), rd, target.contentHash, 0)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, uint64(5), gl.LeafIndex)
	require.Equal(t, mmr.MMRIndex(5), gl.MMRIndex)
	require.Equal(t, idtsBe(555), gl.IDTimestampBe)
	require.Equal(t, uint64(6), next)
}

// Once found, a position is served from the cache with no store reads; a miss
// resumes from where the previous scan stopped.
func TestGrantLeafIndexCachesFoundAndResumesMisses(t *testing.T) {
	ownerID := testLogID(t, "10000000-0000-4000-8000-000000000001")
	log := newGrowingOwnerLog(t, 3)
	target := fixtureEntry{idts: 550, contentHash: sha256.Sum256([]byte("cached"))}
	log.append(entryN(1), entryN(2), entryN(3), entryN(4), entryN(5))

	idx := NewGrantLeafIndex()

	// Miss: leaves 0..4 scanned.
	_, found, err := idx.Find(t.Context(), ownerID, log.reader(), target.contentHash)
	require.NoError(t, err)
	require.False(t, found)

	// The grant lands; the miss resumes at leaf 5, so massif 0 is not read.
	log.append(target)
	rd := log.reader()
	gl, found, err := idx.Find(t.Context(), ownerID, rd, target.contentHash)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, uint64(5), gl.LeafIndex)
	require.Zero(t, rd.readOf(0))

	// Found positions are final: no reads at all.
	rd2 := log.reader()
	again, found, err := idx.Find(t.Context(), ownerID, rd2, target.contentHash)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, gl, again)
	require.Zero(t, rd2.total())

	// Progress is per owner log: another owner starts from leaf 0.
	other := testLogID(t, "30000000-0000-4000-8000-000000000003")
	rd3 := log.reader()
	_, found, err = idx.Find(t.Context(), other, rd3, target.contentHash)
	require.NoError(t, err)
	require.True(t, found)
	require.NotZero(t, rd3.total())
}

func TestVerifyGrantLeafAnchored(t *testing.T) {
	ctx := t.Context()
	log := newGrowingOwnerLog(t, 3)
	target := fixtureEntry{idts: 444, contentHash: sha256.Sum256([]byte("anchored"))}
	log.append(entryN(1), entryN(2), entryN(3), entryN(4), target, entryN(6))
	rd := log.reader()
	gl, found, _, err := ScanGrantLeaf(ctx, rd, target.contentHash, 0)
	require.NoError(t, err)
	require.True(t, found)

	good := LogState{Accumulator: log.accumulator(), Size: log.size}

	t.Run("not covered yet", func(t *testing.T) {
		st := LogState{Accumulator: good.Accumulator, Size: gl.MMRIndex}
		ok, err := VerifyGrantLeafAnchored(ctx, rd, 3, st, gl)
		require.NoError(t, err)
		require.False(t, ok)
	})
	t.Run("covered and reproduces a peak", func(t *testing.T) {
		ok, err := VerifyGrantLeafAnchored(ctx, rd, 3, good, gl)
		require.NoError(t, err)
		require.True(t, ok)
	})
	t.Run("wrong accumulator", func(t *testing.T) {
		bad := make([][32]byte, len(good.Accumulator))
		for i, p := range good.Accumulator {
			p[0] ^= 0xff
			bad[i] = p
		}
		ok, err := VerifyGrantLeafAnchored(ctx, rd, 3, LogState{Accumulator: bad, Size: good.Size}, gl)
		require.Error(t, err)
		require.False(t, ok)
	})
}
