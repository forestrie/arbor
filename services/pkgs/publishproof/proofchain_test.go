package publishproof

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
)

// memMMR is a minimal in-memory mmr.NodeAppender for fixture logs.
type memMMR struct {
	nodes [][]byte
}

func (m *memMMR) Get(i uint64) ([]byte, error) {
	if i >= uint64(len(m.nodes)) {
		return nil, fmt.Errorf("index %d out of range", i)
	}
	return m.nodes[i], nil
}

func (m *memMMR) Append(value []byte) (uint64, error) {
	m.nodes = append(m.nodes, value)
	return uint64(len(m.nodes)), nil
}

// newFixtureMMR builds an MMR of nLeaves distinct hashed leaves and returns
// the store plus the complete mmr sizes observed after each leaf add.
func newFixtureMMR(t *testing.T, nLeaves int) (*memMMR, []uint64) {
	t.Helper()
	store := &memMMR{}
	sizes := make([]uint64, 0, nLeaves)
	h := sha256.New()
	for i := range nLeaves {
		leaf := sha256.Sum256([]byte{byte(i)})
		size, err := mmr.AddHashedLeaf(store, h, leaf[:])
		require.NoError(t, err)
		sizes = append(sizes, size)
	}
	return store, sizes
}

// verifyProofChainLikeContract applies the same algorithm as univocity
// verifyConsistencyProofChain (consistencyReceipt.sol): each proof's paths are
// applied to the accumulator carried forward from the previous step, and the
// rightPeaks are appended. Returns the final accumulator.
func verifyProofChainLikeContract(t *testing.T, initial [][32]byte, proofs []ConsistencyProof) [][32]byte {
	t.Helper()
	acc := initial
	for _, p := range proofs {
		if p.TreeSize1 == 0 {
			acc = append([][32]byte{}, p.RightPeaks...)
			continue
		}
		from := make([][]byte, len(acc))
		for i := range acc {
			from[i] = acc[i][:]
		}
		paths := make([][][]byte, len(p.Paths))
		for i, path := range p.Paths {
			paths[i] = make([][]byte, len(path))
			for j := range path {
				paths[i][j] = path[j][:]
			}
		}
		roots, err := mmr.ConsistentRoots(sha256.New(), p.TreeSize1-1, from, paths)
		require.NoError(t, err)
		var next [][32]byte
		for _, r := range roots {
			next = append(next, [32]byte(r))
		}
		acc = append(next, p.RightPeaks...)
	}
	return acc
}

func peaks32(t *testing.T, store *memMMR, mmrSize uint64) [][32]byte {
	t.Helper()
	hashes, err := mmr.PeakHashes(store, mmrSize-1)
	require.NoError(t, err)
	out := make([][32]byte, len(hashes))
	for i := range hashes {
		out[i] = [32]byte(hashes[i])
	}
	return out
}

// A single extend step: the chained proofs must carry the on-chain accumulator
// for size A to exactly the accumulator the sealer signed for size B.
func TestBuildConsistencyProofExtendReachesTargetAccumulator(t *testing.T) {
	store, sizes := newFixtureMMR(t, 8)
	sizeA, sizeB := sizes[3], sizes[6] // 7 -> 11, the draft's worked example shape

	proof, err := BuildConsistencyProof(store, sizeA, sizeB)
	require.NoError(t, err)
	require.Equal(t, sizeA, proof.TreeSize1)
	require.Equal(t, sizeB, proof.TreeSize2)

	final := verifyProofChainLikeContract(t, peaks32(t, store, sizeA), []ConsistencyProof{proof})
	require.Equal(t, peaks32(t, store, sizeB), final)
}

// First checkpoint of a log: no prior on-chain state, the proof carries the
// full accumulator as rightPeaks and no paths (FOR-314 pinned composition).
func TestBuildConsistencyProofFirstCheckpointIsRightPeaksOnly(t *testing.T) {
	store, sizes := newFixtureMMR(t, 2)

	proof, err := BuildConsistencyProof(store, 0, sizes[1])
	require.NoError(t, err)
	require.Equal(t, uint64(0), proof.TreeSize1)
	require.Equal(t, sizes[1], proof.TreeSize2)
	require.Empty(t, proof.Paths)
	require.Equal(t, peaks32(t, store, sizes[1]), proof.RightPeaks)
}

// Publisher catch-up across multiple seals: one proof per sealed step, chained
// from the on-chain size through every intermediate sealed size (FOR-314).
func TestBuildConsistencyProofChainOneProofPerSeal(t *testing.T) {
	store, sizes := newFixtureMMR(t, 8)
	sealedSizes := []uint64{sizes[1], sizes[4], sizes[7]}

	proofs, err := BuildConsistencyProofChain(store, 0, sealedSizes)
	require.NoError(t, err)
	require.Len(t, proofs, 3)
	require.Equal(t, uint64(0), proofs[0].TreeSize1)
	require.Equal(t, sizes[1], proofs[0].TreeSize2)
	require.Equal(t, sizes[1], proofs[1].TreeSize1)
	require.Equal(t, sizes[4], proofs[1].TreeSize2)
	require.Equal(t, sizes[4], proofs[2].TreeSize1)
	require.Equal(t, sizes[7], proofs[2].TreeSize2)

	final := verifyProofChainLikeContract(t, nil, proofs)
	require.Equal(t, peaks32(t, store, sizes[7]), final)
}
