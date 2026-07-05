package publishproof

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/mmr"
)

// ownerNodeGetter reads mmr nodes across all of an owner log's massifs, routing
// each global node index to the massif blob that stores it. A single massif
// context only serves its own nodes plus the peaks carried into it, so it
// cannot supply the sibling nodes an inclusion proof needs once the path leaves
// the leaf's massif; this getter closes that gap for multi-massif owner logs
// (R2 in plan-2607-03). Loaded massifs are cached for the life of the getter.
type ownerNodeGetter struct {
	ctx    context.Context
	reader massifs.ObjectReader
	height uint8
	cache  map[uint32]*massifs.MassifContext
}

func newOwnerNodeGetter(ctx context.Context, reader massifs.ObjectReader, height uint8) *ownerNodeGetter {
	return &ownerNodeGetter{ctx: ctx, reader: reader, height: height, cache: map[uint32]*massifs.MassifContext{}}
}

func (g *ownerNodeGetter) Get(i uint64) ([]byte, error) {
	mi := uint32(massifs.MassifIndexFromMMRIndex(g.height, i))
	mc, ok := g.cache[mi]
	if !ok {
		m, err := massifs.GetMassifContext(g.ctx, g.reader, mi)
		if err != nil {
			return nil, fmt.Errorf("read owner massif %d for node %d: %w", mi, i, err)
		}
		mc = &m
		g.cache[mi] = mc
	}
	return mc.Get(i)
}

// verifyGrantInclusion recomputes the accumulator peak the grant leaf commits
// to from the inclusion proof and requires it to be one of the owner's on-chain
// accumulator peaks. This is a self-check on the assembled proof: a mis-routed
// node read or a stale massif produces a peak absent from the on-chain
// accumulator and is rejected here rather than shipped as a calldata that the
// contract would revert.
func verifyGrantInclusion(leaf [32]byte, inclusion InclusionProof, accumulator [][32]byte) error {
	path := make([][]byte, len(inclusion.Path))
	for i := range inclusion.Path {
		path[i] = inclusion.Path[i][:]
	}
	root := mmr.IncludedRoot(sha256.New(), inclusion.Index, leaf[:], path)
	for _, peak := range accumulator {
		if string(peak[:]) == string(root) {
			return nil
		}
	}
	return fmt.Errorf("grant inclusion proof does not reproduce any owner on-chain accumulator peak")
}
