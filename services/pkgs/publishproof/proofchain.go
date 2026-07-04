package publishproof

import (
	"crypto/sha256"
	"fmt"

	"github.com/forestrie/go-merklelog/mmr"
)

// NodeGetter provides mmr node values by index. Massif contexts and the
// s3storage merklelog readers satisfy this.
type NodeGetter interface {
	Get(i uint64) ([]byte, error)
}

// BuildConsistencyProof builds the univocity ConsistencyProof carrying the
// accumulator of MMR(fromSize) to the accumulator of MMR(toSize), per the
// draft consistent_roots algorithm the contract implements. fromSize 0 means
// the log has no on-chain state yet: no paths, the full target accumulator as
// rightPeaks. Both sizes must be complete mmr sizes; toSize is typically a
// sealed checkpoint's mmrSize.
func BuildConsistencyProof(store NodeGetter, fromSize, toSize uint64) (ConsistencyProof, error) {
	if toSize <= fromSize {
		return ConsistencyProof{}, fmt.Errorf("toSize %d must be greater than fromSize %d", toSize, fromSize)
	}

	peaksTo, err := mmr.PeakHashes(store, toSize-1)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("peaks of target size %d: %w", toSize, err)
	}

	proof := ConsistencyProof{
		TreeSize1: fromSize,
		TreeSize2: toSize,
		Paths:     [][][32]byte{},
	}

	if fromSize == 0 {
		proof.RightPeaks = toBytes32Slice(peaksTo)
		return proof, nil
	}

	cp, err := mmr.IndexConsistencyProof(store, fromSize-1, toSize-1)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("consistency proof %d -> %d: %w", fromSize, toSize, err)
	}

	peaksFrom, err := mmr.PeakHashes(store, fromSize-1)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("peaks of origin size %d: %w", fromSize, err)
	}

	// The proven roots are a prefix of the target accumulator; whatever the
	// paths do not reach is carried explicitly as rightPeaks.
	roots, err := mmr.ConsistentRoots(sha256.New(), fromSize-1, peaksFrom, cp.Path)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("consistent roots %d -> %d: %w", fromSize, toSize, err)
	}
	for i := range roots {
		if !equalBytes32(roots[i], peaksTo[i]) {
			return ConsistencyProof{}, fmt.Errorf("proven root %d does not match target accumulator", i)
		}
	}

	for _, path := range cp.Path {
		proof.Paths = append(proof.Paths, toBytes32Slice(path))
	}
	proof.RightPeaks = toBytes32Slice(peaksTo[len(roots):])
	return proof, nil
}

// BuildConsistencyProofChain builds one ConsistencyProof per sealed step,
// chaining from the on-chain size through each sealed size in order. This is
// the composition the FOR-314 spike pins for a publisher catching up over
// multiple seals with a single publishCheckpoint.
func BuildConsistencyProofChain(store NodeGetter, fromSize uint64, sealedSizes []uint64) ([]ConsistencyProof, error) {
	if len(sealedSizes) == 0 {
		return nil, fmt.Errorf("at least one sealed size is required")
	}
	proofs := make([]ConsistencyProof, 0, len(sealedSizes))
	prev := fromSize
	for _, size := range sealedSizes {
		proof, err := BuildConsistencyProof(store, prev, size)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, proof)
		prev = size
	}
	return proofs, nil
}

func toBytes32Slice(in [][]byte) [][32]byte {
	out := make([][32]byte, len(in))
	for i := range in {
		if len(in[i]) != 32 {
			panic(fmt.Sprintf("publishproof: mmr node %d is %d bytes, want 32", i, len(in[i])))
		}
		out[i] = [32]byte(in[i])
	}
	return out
}

func equalBytes32(a, b []byte) bool {
	return len(a) == 32 && len(b) == 32 && [32]byte(a) == [32]byte(b)
}
