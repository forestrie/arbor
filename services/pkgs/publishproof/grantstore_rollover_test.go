package publishproof

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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

	// A parallel flat in-memory MMR over the same leaves is an independent
	// accumulator oracle: it materialises every node — including a peak whose
	// children live in different massif blobs — which no per-blob reader can
	// hash. The on-chain accumulator the publisher checks against would come
	// from logState; here the oracle stands in for it.
	oracle := &memMMR{}
	oracleHasher := sha256.New()

	var size uint64
	for _, e := range entries {
		var idtsBE [8]byte
		binary.BigEndian.PutUint64(idtsBE[:], e.idts)
		leaf := sha256.Sum256(append(idtsBE[:], e.contentHash[:]...))
		size, err = mc.AddIndexedEntry(leaf[:])
		if errors.Is(err, massifs.ErrMassifFull) {
			// Persist the full massif and re-obtain an append context: GetAppendContext
			// reloads the committed head and reconstructs the peak stack (via
			// InitAppendContext) so the new massif carries the prior massifs' peaks —
			// necessary once a later massif's nodes must hash a peak from an earlier
			// one. This is the canonical roll (mmrtesting builder); StartNextMassif on
			// the in-memory writer does not persist/reload that stack.
			require.NoError(t, massifs.CommitContext(ctx, store, &mc))
			mc, err = massifs.GetAppendContext(ctx, store, 0, rolloverMassifHeight)
			require.NoError(t, err)
			size, err = mc.AddIndexedEntry(leaf[:])
		}
		require.NoError(t, err)
		require.NoError(t, mc.IndexLeaf(e.idts, e.contentHash[:]))

		oracleSize, err := mmr.AddHashedLeaf(oracle, oracleHasher, leaf[:])
		require.NoError(t, err)
		require.Equal(t, size, oracleSize, "oracle and massif log must agree on mmr size")
	}
	require.NoError(t, massifs.CommitContext(ctx, store, &mc))

	// A fresh reader so publisher reads are served from the committed objects,
	// not the writer's in-memory context.
	rfactory, err := merklelog.NewFactory(client, rolloverMassifHeight, logger)
	require.NoError(t, err)
	reader, err := rfactory.NewStore(massifstorage.LogID(logID))
	require.NoError(t, err)
	require.NoError(t, reader.SelectLog(ctx, massifstorage.LogID(logID)))

	// The on-chain accumulator, from the oracle (materialises cross-massif peaks).
	peaks, err := mmr.PeakHashes(oracle, size-1)
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
// correct *global* mmr index (local ordinal -> global via mc.Start.FirstIndex),
// and its inclusion proof verifies against the owner's on-chain accumulator.
// This guards the primary R2 defect (grantstore.go used the massif-local ordinal
// as a global leaf index — correct only for a single-massif owner log). The
// separate boundary-crossing routing half of the fix (ownerNodeGetter) is guarded
// by TestGrantInclusionProofCrossesMassifBoundary.
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

	// The grant leaf's inclusion proof, read through the ownerNodeGetter,
	// reproduces one of the owner's on-chain accumulator peaks. (Here the two
	// massifs sit under separate accumulator peaks, so this leaf's path stays
	// within massif 1; a path that actually spans massifs is exercised by
	// TestGrantInclusionProofCrossesMassifBoundary.)
	nodes := newOwnerNodeGetter(ctx, reader, rolloverMassifHeight)
	inclusion, err := BuildInclusionProof(nodes, size, got)
	require.NoError(t, err)
	require.NoError(t, verifyGrantInclusion(leaf, inclusion, acc))
}

// A grant leaf in massif 0 of an owner log whose massifs are unified under a
// single accumulator peak has an authentication path that reaches a node stored
// in a *later* massif. Assembling that proof therefore requires ownerNodeGetter's
// cross-massif routing (MassifIndexFromMMRIndex -> owning blob); a single massif
// context cannot supply the far node. This is the second half of the R2 fix
// (plan-2607-03), which TestFindGrantLeafMMRIndexMultiMassif does not exercise
// because there the two massifs sit under separate peaks.
func TestGrantInclusionProofCrossesMassifBoundary(t *testing.T) {
	ctx := t.Context()

	// 8 entries at 4 leaves/massif => two *full* massifs (leaves 0..3 and 4..7)
	// unified under one mmr peak. A massif-0 leaf's path then needs the massif-1
	// subtree peak.
	entries := make([]fixtureEntry, 8)
	entries[0] = fixtureEntry{idts: 0, contentHash: sha256.Sum256([]byte("root-self-grant"))}
	for i := 1; i < 8; i++ {
		entries[i] = fixtureEntry{
			idts:        uint64(i) * 100,
			contentHash: sha256.Sum256([]byte(fmt.Sprintf("g%d", i))),
		}
	}
	logID := mustHex(t, "1112131415161718191a1b1c1d1e1f20")
	reader, size, acc := rolledOwnerLog(t, logID, entries)

	head, err := reader.HeadIndex(ctx, massifstorage.ObjectMassifData)
	require.NoError(t, err)
	require.Equal(t, uint32(1), head, "fixture must span two full massifs")

	// The root self-grant at leaf 0 lives in massif 0.
	grant := entries[0]
	leaf := leafCommitment(grant)
	var idts [8]byte
	binary.BigEndian.PutUint64(idts[:], grant.idts)

	node, err := FindGrantLeafMMRIndex(ctx, reader, size, idts, leaf)
	require.NoError(t, err)
	require.Equal(t, uint64(0), node, "the leaf-0 self-grant is global mmr node 0")

	// The authentication path must read a node stored in massif 1, so the proof
	// genuinely spans the massif boundary (independent of how it is assembled).
	pathIdx, err := mmr.InclusionProofPath(size-1, node)
	require.NoError(t, err)
	touched := map[uint64]bool{}
	for _, ni := range pathIdx {
		touched[massifs.MassifIndexFromMMRIndex(rolloverMassifHeight, ni)] = true
	}
	require.True(t, touched[1], "a massif-0 grant's path must read a node from massif 1")
	require.Greater(t, len(touched), 1, "path must span more than one massif")

	// Assembled through the boundary-crossing ownerNodeGetter, the proof reads the
	// massif-1 node its path needs and reproduces the owner's on-chain accumulator
	// (the oracle) — the routing half of the R2 fix. A single massif context could
	// not supply the far node at all (its Get is bounded to its own blob).
	nodes := newOwnerNodeGetter(ctx, reader, rolloverMassifHeight)
	inclusion, err := BuildInclusionProof(nodes, size, node)
	require.NoError(t, err)
	require.NoError(t, verifyGrantInclusion(leaf, inclusion, acc))
}
