package publishproof

import (
	"crypto/sha256"
	"testing"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
)

// The grant inclusion proof must land the leaf commitment on a peak of the
// owner log's accumulator — that is exactly what LibLogState.verifyInclusion
// checks on-chain.
func TestBuildInclusionProofReachesOwnerAccumulatorPeak(t *testing.T) {
	store, sizes := newFixtureMMR(t, 5)
	ownerSize := sizes[4]

	// Prove the third leaf; MMRIndex converts leaf index to node index.
	leafNodeIndex := mmr.MMRIndex(2)
	leaf, err := store.Get(leafNodeIndex)
	require.NoError(t, err)

	proof, err := BuildInclusionProof(store, ownerSize, leafNodeIndex)
	require.NoError(t, err)
	require.Equal(t, leafNodeIndex, proof.Index)

	path := make([][]byte, len(proof.Path))
	for i := range proof.Path {
		path[i] = proof.Path[i][:]
	}
	root := mmr.IncludedRoot(sha256.New(), leafNodeIndex, leaf, path)
	require.Contains(t, peaks32(t, store, ownerSize), [32]byte(root))
}
