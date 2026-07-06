package publishproof

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
)

// sealedMultiMassifLog builds a log spanning numMassifs massifs and seals a
// format-v3 checkpoint at each massif boundary (embedded per-seal consistency
// proof, sealed(K-1) -> sealed(K)), mirroring the production sealer. It returns
// a fresh reader over the committed objects and the sealed size of each massif.
func sealedMultiMassifLog(t *testing.T, logID []byte, sealer *fixtureSealer, numMassifs int) (*merklelog.Store, []uint64) {
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

	var sealed []uint64
	prev := uint64(0)
	seal := func() {
		require.NoError(t, massifs.CommitContext(ctx, store, &mc))
		size := mc.RangeCount()
		peaks, err := mmr.PeakHashes(&mc, size-1)
		require.NoError(t, err)
		proof, err := massifs.BuildConsistencyProof(&mc, prev, size)
		require.NoError(t, err)
		data, err := massifs.SignCheckpointReceipt(
			sealer.coseSigner, proof, peaks, massifs.WithPeakReceipts([]byte("k")))
		require.NoError(t, err)
		require.NoError(t, store.Put(ctx, mc.Start.MassifIndex, massifstorage.ObjectCheckpoint, data, false))
		sealed = append(sealed, size)
		prev = size
	}

	var n uint64
	for len(sealed) < numMassifs {
		var leaf [32]byte
		binary.BigEndian.PutUint64(leaf[:8], n)
		n++
		_, err := mc.AddIndexedEntry(leaf[:])
		if errors.Is(err, massifs.ErrMassifFull) {
			seal() // seal the now-full massif, then roll to the next
			mc, err = massifs.GetAppendContext(ctx, store, 0, rolloverMassifHeight)
			require.NoError(t, err)
			_, err = mc.AddIndexedEntry(leaf[:])
		}
		require.NoError(t, err)
	}

	rf, err := merklelog.NewFactory(client, rolloverMassifHeight, logger)
	require.NoError(t, err)
	reader, err := rf.NewStore(massifstorage.LogID(logID))
	require.NoError(t, err)
	require.NoError(t, reader.SelectLog(ctx, massifstorage.LogID(logID)))
	return reader, sealed
}

func headProofs(t *testing.T, reader *merklelog.Store, massifIndex uint32) []ConsistencyProof {
	t.Helper()
	cp, err := massifs.GetCheckpoint(t.Context(), reader, massifIndex)
	require.NoError(t, err)
	rec, err := DecodeCheckpointReceipt(cp.Raw)
	require.NoError(t, err)
	return rec.ConsistencyProofs
}

// The chain relayed from the embedded per-seal proofs bridges the on-chain size
// to the head seal across several massifs, contiguously, reading only checkpoint
// objects (no massif node data).
func TestBuildEmbeddedProofChainMultiMassif(t *testing.T) {
	logID := mustHex(t, "0102030405060708090a0b0c0d0e0f10")
	reader, sealed := sealedMultiMassifLog(t, logID, newFixtureSealer(t), 3)
	require.Len(t, sealed, 3) // sealed[0..2] are massif-boundary sizes

	// Catch up from the massif-0 seal to the massif-2 seal: chain = [1, 2].
	chain, err := BuildEmbeddedProofChain(t.Context(), reader, sealed[0], 2, headProofs(t, reader, 2))
	require.NoError(t, err)
	require.Len(t, chain, 2)
	require.Equal(t, sealed[0], chain[0].TreeSize1, "chain starts at the on-chain size")
	require.Equal(t, sealed[1], chain[0].TreeSize2)
	require.Equal(t, chain[0].TreeSize2, chain[1].TreeSize1, "links are contiguous")
	require.Equal(t, sealed[2], chain[1].TreeSize2, "chain ends at the head seal")

	// One-massif catch-up returns the single head link with no extra reads.
	one, err := BuildEmbeddedProofChain(t.Context(), reader, sealed[1], 2, headProofs(t, reader, 2))
	require.NoError(t, err)
	require.Len(t, one, 1)
	require.Equal(t, sealed[1], one[0].TreeSize1)

	// An on-chain size that no link starts at (between boundaries) is rejected.
	_, err = BuildEmbeddedProofChain(t.Context(), reader, sealed[0]+1, 2, headProofs(t, reader, 2))
	require.Error(t, err)
}
