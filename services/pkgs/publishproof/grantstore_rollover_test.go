package publishproof

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/forestrie/go-merklelog/urkle"
	"github.com/stretchr/testify/require"
)

// rolloverMassifHeight is deliberately tiny (2^(3-1) = 4 leaves per massif) so a
// handful of entries rolls the owner authority log past its first massif. That
// is the condition FindGrantLeafMMRIndex / GrantLeafMMRIndex must handle: once
// the grant leaf lives in a massif with FirstIndex != 0, a massif-local leaf
// ordinal is no longer a global mmr leaf index (R2 in plan-2607-03 / FOR-329).
const rolloverMassifHeight = uint8(3)

// rolledOwnerLog builds a real owner authority log in the R2 object layout that
// spans >= 2 massifs, indexing each (idtimestamp, contentHash) entry exactly as
// ranger's committer does (leaf = sha256(idtimestampBe || contentHash)). It
// returns a fresh reader over the committed objects, the full mmr size, and the
// on-chain accumulator peaks for that size.
func rolledOwnerLog(t *testing.T, logID []byte, entries []fixtureEntry) (*merklelog.Store, uint64, [][32]byte) {
	t.Helper()
	ctx := t.Context()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := newMemObjectClient()

	factory, err := merklelog.NewFactory(client, rolloverMassifHeight, logger)
	require.NoError(t, err)
	store, err := factory.NewStore(massifstorage.LogID(logID))
	require.NoError(t, err)
	require.NoError(t, store.SelectLog(ctx, massifstorage.LogID(logID)))

	mc, err := massifs.CreateFirstMassifContext(ctx, 0, rolloverMassifHeight)
	require.NoError(t, err)

	var size uint64
	for _, e := range entries {
		var idtsBE [8]byte
		binary.BigEndian.PutUint64(idtsBE[:], e.idts)
		leaf := sha256.Sum256(append(idtsBE[:], e.contentHash[:]...))
		size, err = mc.AddIndexedEntry(leaf[:])
		if errors.Is(err, massifs.ErrMassifFull) {
			// Persist the full massif, roll to the next one (StartNextMassif reads
			// the previous massif's data to seed the new blob), then re-add.
			require.NoError(t, massifs.CommitContext(ctx, store, &mc))
			require.NoError(t, mc.StartNextMassif())
			size, err = mc.AddIndexedEntry(leaf[:])
		}
		require.NoError(t, err)
		require.NoError(t, mc.IndexLeaf(e.idts, e.contentHash[:]))
	}
	require.NoError(t, massifs.CommitContext(ctx, store, &mc))

	// A fresh reader so publisher reads are served from the committed objects,
	// not the writer's in-memory context.
	rfactory, err := merklelog.NewFactory(client, rolloverMassifHeight, logger)
	require.NoError(t, err)
	reader, err := rfactory.NewStore(massifstorage.LogID(logID))
	require.NoError(t, err)
	require.NoError(t, reader.SelectLog(ctx, massifstorage.LogID(logID)))

	// The on-chain accumulator for the full log, read across all massifs.
	nodes := newOwnerNodeGetter(ctx, reader, rolloverMassifHeight)
	peaks, err := mmr.PeakHashes(nodes, size-1)
	require.NoError(t, err)
	acc := make([][32]byte, len(peaks))
	for i, p := range peaks {
		copy(acc[i][:], p)
	}
	return reader, size, acc
}

func leafCommitment(e fixtureEntry) [32]byte {
	var idtsBE [8]byte
	binary.BigEndian.PutUint64(idtsBE[:], e.idts)
	return sha256.Sum256(append(idtsBE[:], e.contentHash[:]...))
}

// A grant whose leaf lives in a massif past the first one is located at its
// correct global mmr index, and its inclusion proof — whose path crosses the
// massif boundary — verifies against the owner's on-chain accumulator. This is
// the end-to-end exercise the merged R2 fix (grantstore.go: local ordinal ->
// global index via mc.Start.FirstIndex, and the boundary-crossing ownerNodeGetter)
// was missing a fixture for; it is a regression guard against reintroducing the
// head-massif-only / massif-local-ordinal assumption.
func TestFindGrantLeafMMRIndexMultiMassif(t *testing.T) {
	ctx := t.Context()

	// 4 leaves/massif: leaves 0..3 land in massif 0, leaves 4..5 in massif 1.
	entries := []fixtureEntry{
		{idts: 0, contentHash: sha256.Sum256([]byte("root-self-grant"))}, // leaf 0, massif 0
		{idts: 100, contentHash: sha256.Sum256([]byte("g1"))},            // leaf 1, massif 0
		{idts: 200, contentHash: sha256.Sum256([]byte("g2"))},            // leaf 2, massif 0
		{idts: 300, contentHash: sha256.Sum256([]byte("g3"))},            // leaf 3, massif 0 (fills it)
		{idts: 400, contentHash: sha256.Sum256([]byte("g4"))},            // leaf 4, massif 1 ordinal 0
		{idts: 500, contentHash: sha256.Sum256([]byte("g5"))},            // leaf 5, massif 1 ordinal 1
	}
	logID := mustHex(t, "0102030405060708090a0b0c0d0e0f10")
	reader, size, acc := rolledOwnerLog(t, logID, entries)

	// Sanity: the log really did roll — the head massif is index 1.
	head, err := reader.HeadIndex(ctx, massifstorage.ObjectMassifData)
	require.NoError(t, err)
	require.Equal(t, uint32(1), head, "fixture must span two massifs")

	// The target grant is the last entry: global leaf 5, massif 1, local ordinal 1.
	target := entries[5]
	const localOrdinal = uint64(1)
	leaf := leafCommitment(target)

	var idts [8]byte
	binary.BigEndian.PutUint64(idts[:], target.idts)

	// FindGrantLeafMMRIndex walks massif 0 (miss) then massif 1 (hit) and returns
	// the grant leaf's *global* mmr node index.
	got, err := FindGrantLeafMMRIndex(ctx, reader, size, idts, leaf)
	require.NoError(t, err)

	// The correct global index is first-massif-index + local ordinal, taken from
	// massif 1's own start header.
	mc1, err := massifs.GetMassifContext(ctx, reader, 1)
	require.NoError(t, err)
	require.NotZero(t, mc1.Start.FirstIndex, "massif 1 must have a non-zero FirstIndex")
	wantGlobal := urkle.LeafOrdinalToMMRIndex(mc1.Start.FirstIndex, localOrdinal)
	require.Equal(t, wantGlobal, got)

	// Regression guard: the pre-fix code used the massif-local ordinal as a global
	// leaf index (mmr.MMRIndex(localOrdinal)). That value differs from the correct
	// global index, so a reintroduction of the bug would fail the assertion above.
	buggyLocal := mmr.MMRIndex(localOrdinal)
	require.NotEqual(t, buggyLocal, got,
		"global index must not collapse to the massif-local computation")

	// The single head-massif view alone cannot find a grant that rolled into it
	// from an earlier ordinal space unless the first-index mapping is applied:
	// searching massif 0 for this grant misses (its idtimestamp is not in range).
	mc0, err := massifs.GetMassifContext(ctx, reader, 0)
	require.NoError(t, err)
	_, err = GrantLeafMMRIndex(&mc0, size, idts, leaf)
	require.ErrorIs(t, err, ErrGrantLeafNotFound)

	// The inclusion proof for the grant leaf crosses the massif boundary (its
	// path needs sibling nodes from massif 0), read through the ownerNodeGetter,
	// and reproduces one of the owner's on-chain accumulator peaks.
	nodes := newOwnerNodeGetter(ctx, reader, rolloverMassifHeight)
	inclusion, err := BuildInclusionProof(nodes, size, got)
	require.NoError(t, err)
	require.NotEmpty(t, inclusion.Path, "a multi-massif inclusion proof has a non-empty path")
	require.NoError(t, verifyGrantInclusion(leaf, inclusion, acc))
}
