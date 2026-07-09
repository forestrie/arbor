package publishproof

import (
	"crypto/sha256"
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
// a fresh reader over the committed objects, the sealed size of each massif, and
// a flat in-memory MMR oracle over the same leaves (materialises cross-massif
// peaks so the on-chain accumulator at any size can be recovered).
func sealedMultiMassifLog(t *testing.T, logID []byte, sealer *fixtureSealer, numMassifs int) (*merklelog.Store, []uint64, *memMMR) {
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

	oracle := &memMMR{}
	oracleHasher := sha256.New()
	appendOracle := func(leaf []byte) {
		_, err := mmr.AddHashedLeaf(oracle, oracleHasher, leaf)
		require.NoError(t, err)
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
		appendOracle(leaf[:])
	}

	rf, err := merklelog.NewFactory(client, rolloverMassifHeight, logger)
	require.NoError(t, err)
	reader, err := rf.NewStore(massifstorage.LogID(logID))
	require.NoError(t, err)
	require.NoError(t, reader.SelectLog(ctx, massifstorage.LogID(logID)))
	return reader, sealed, oracle
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
// objects (no massif node data) — and it VERIFIES like the contract does,
// reaching the head seal's accumulator.
func TestBuildEmbeddedProofChainMultiMassif(t *testing.T) {
	logID := mustHex(t, "0102030405060708090a0b0c0d0e0f10")
	reader, sealed, oracle := sealedMultiMassifLog(t, logID, newFixtureSealer(t), 3)
	require.Len(t, sealed, 3) // sealed[0..2] are massif-boundary sizes

	// Catch up from the massif-0 seal to the massif-2 seal: chain = [1, 2].
	chain, err := BuildEmbeddedProofChain(t.Context(), reader, sealed[0], 2, headProofs(t, reader, 2))
	require.NoError(t, err)
	require.Len(t, chain, 2)
	require.Equal(t, sealed[0], chain[0].TreeSize1, "chain starts at the on-chain size")
	require.Equal(t, chain[0].TreeSize2, chain[1].TreeSize1, "links are contiguous")
	require.Equal(t, sealed[2], chain[1].TreeSize2, "chain ends at the head seal")

	// Crypto: replaying the relayed chain like the contract, seeded with the
	// on-chain accumulator at sealed[0], must reach the head seal's accumulator.
	final := verifyProofChainLikeContract(t, peaks32(t, oracle, sealed[0]), chain)
	require.Equal(t, peaks32(t, oracle, sealed[2]), final)

	// One-massif catch-up returns the single head link with no extra reads.
	one, err := BuildEmbeddedProofChain(t.Context(), reader, sealed[1], 2, headProofs(t, reader, 2))
	require.NoError(t, err)
	require.Len(t, one, 1)
	require.Equal(t, sealed[1], one[0].TreeSize1)

	// An on-chain size that lags *inside* a massif (no embedded link starts at
	// it) is rebuilt from that massif's nodes and re-based to the on-chain size,
	// then verifies from the on-chain accumulator at that size.
	mid := sealed[0] + 1
	rebased, err := BuildEmbeddedProofChain(t.Context(), reader, mid, 2, headProofs(t, reader, 2))
	require.NoError(t, err)
	require.Equal(t, mid, rebased[0].TreeSize1, "first link re-based to the on-chain size")
	require.Equal(t, sealed[2], rebased[len(rebased)-1].TreeSize2, "chain ends at the head seal")
	finalMid := verifyProofChainLikeContract(t, peaks32(t, oracle, mid), rebased)
	require.Equal(t, peaks32(t, oracle, sealed[2]), finalMid)
}

// Bootstrap: catching up from an unanchored log (on-chain size 0) walks to the
// genesis checkpoint (treeSize1==0) and verifies from an empty accumulator.
func TestBuildEmbeddedProofChainBootstrap(t *testing.T) {
	logID := mustHex(t, "1112131415161718191a1b1c1d1e1f20")
	reader, sealed, oracle := sealedMultiMassifLog(t, logID, newFixtureSealer(t), 3)

	chain, err := BuildEmbeddedProofChain(t.Context(), reader, 0, 2, headProofs(t, reader, 2))
	require.NoError(t, err)
	require.Len(t, chain, 3)
	require.Equal(t, uint64(0), chain[0].TreeSize1, "first link is the genesis (treeSize1==0)")
	require.Equal(t, sealed[2], chain[2].TreeSize2)

	// Verify from an empty initial accumulator (the contract's bootstrap seed).
	final := verifyProofChainLikeContract(t, [][32]byte{}, chain)
	require.Equal(t, peaks32(t, oracle, sealed[2]), final)
}

// A single massif re-sealed at two partial sizes leaves an embedded checkpoint
// proof whose base is the *last partial seal* (>0), not the massif boundary —
// the production overwrite bug (a 2-leaf log's massif-0 checkpoint was (1 -> 3)).
// Catching up a never-anchored log (on-chain size 0) must re-base that proof to
// (0 -> head) from the massif and verify from the empty accumulator.
func TestBuildEmbeddedProofChainReBaseFirstAnchorAfterReseal(t *testing.T) {
	ctx := t.Context()
	logID := mustHex(t, "2122232425262728292a2b2c2d2e2f30")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := newMemObjectClient()
	sealer := newFixtureSealer(t)
	factory, err := merklelog.NewFactory(client, rolloverMassifHeight, logger)
	require.NoError(t, err)
	store, err := factory.NewStore(massifstorage.LogID(logID))
	require.NoError(t, err)
	require.NoError(t, store.SelectLog(ctx, massifstorage.LogID(logID)))
	mc, err := massifs.CreateFirstMassifContext(ctx, 0, rolloverMassifHeight)
	require.NoError(t, err)

	oracle := &memMMR{}
	oh := sha256.New()
	add := func(n uint64) {
		var leaf [32]byte
		binary.BigEndian.PutUint64(leaf[:8], n)
		_, err := mc.AddIndexedEntry(leaf[:])
		require.NoError(t, err)
		_, err = mmr.AddHashedLeaf(oracle, oh, leaf[:])
		require.NoError(t, err)
	}

	// seal writes a checkpoint whose proof base is the previous seal size — the
	// overwrite that loses the boundary (0) on re-seal.
	var prev uint64
	seal := func() uint64 {
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
		prev = size
		return size
	}

	add(0)
	require.Greater(t, seal(), uint64(0)) // checkpoint (0 -> s1)
	add(1)
	s2 := seal() // checkpoint (s1 -> s2): base is the partial seal, boundary 0 lost

	rf, err := merklelog.NewFactory(client, rolloverMassifHeight, logger)
	require.NoError(t, err)
	reader, err := rf.NewStore(massifstorage.LogID(logID))
	require.NoError(t, err)
	require.NoError(t, reader.SelectLog(ctx, massifstorage.LogID(logID)))

	head := headProofs(t, reader, 0)
	require.Greater(t, head[0].TreeSize1, uint64(0),
		"embedded base is the last partial seal, not the boundary")

	// On-chain size 0: re-base (s1 -> s2) to (0 -> s2) from the massif.
	chain, err := BuildEmbeddedProofChain(ctx, reader, 0, 0, head)
	require.NoError(t, err)
	require.Len(t, chain, 1)
	require.Equal(t, uint64(0), chain[0].TreeSize1, "re-based to on-chain size 0")
	require.Equal(t, s2, chain[0].TreeSize2)

	final := verifyProofChainLikeContract(t, [][32]byte{}, chain)
	require.Equal(t, peaks32(t, oracle, s2), final)
}
