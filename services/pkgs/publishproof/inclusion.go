package publishproof

import (
	"fmt"

	"github.com/forestrie/go-merklelog/mmr"
)

// BuildInclusionProof builds the univocity InclusionProof for the node at
// nodeIndex in the owner log of mmrSize. The contract verifies the proven
// root is a member of the owner log's on-chain accumulator, so mmrSize must
// match the on-chain state the proof will be checked against.
func BuildInclusionProof(store NodeGetter, mmrSize, nodeIndex uint64) (InclusionProof, error) {
	if nodeIndex >= mmrSize {
		return InclusionProof{}, fmt.Errorf("node index %d not in mmr of size %d", nodeIndex, mmrSize)
	}
	path, err := mmr.InclusionProof(store, mmrSize-1, nodeIndex)
	if err != nil {
		return InclusionProof{}, fmt.Errorf("inclusion proof for node %d in size %d: %w", nodeIndex, mmrSize, err)
	}
	return InclusionProof{Index: nodeIndex, Path: toBytes32Slice(path)}, nil
}
