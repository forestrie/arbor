package publishproof

import (
	"context"
	"fmt"

	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/mmr"
)

// SealedState is a sealed checkpoint recovered from the public R2 objects:
// the sealed mmr size from the checkpoint payload and the accumulator
// recomputed from the massif nodes (the sealer detaches peaks from the signed
// state, so verifiers always recover them from the log data).
type SealedState struct {
	MMRSize     uint64
	Accumulator [][32]byte
}

// ReadSealedState reads the checkpoint object for massifIndex and recovers
// the sealed accumulator from the massif data. The reader is an R2-layout
// object store for a selected log (s3storage merklelog Store or compatible).
func ReadSealedState(
	ctx context.Context, reader massifs.ObjectReader, massifIndex uint32,
) (SealedState, error) {
	checkpoint, err := massifs.GetCheckpoint(ctx, reader, massifIndex)
	if err != nil {
		return SealedState{}, fmt.Errorf("read checkpoint %d: %w", massifIndex, err)
	}
	if checkpoint.MMRSize == 0 {
		return SealedState{}, fmt.Errorf("checkpoint %d has zero mmr size", massifIndex)
	}
	mc, err := massifs.GetMassifContext(ctx, reader, massifIndex)
	if err != nil {
		return SealedState{}, fmt.Errorf("read massif %d: %w", massifIndex, err)
	}
	peaks, err := mmr.PeakHashes(&mc, checkpoint.MMRSize-1)
	if err != nil {
		return SealedState{}, fmt.Errorf("recover sealed accumulator: %w", err)
	}
	return SealedState{
		MMRSize:     checkpoint.MMRSize,
		Accumulator: toBytes32Slice(peaks),
	}, nil
}

// BuildCheckpointProof reads the sealed checkpoint at massifIndex and builds
// the consistency proof carrying the on-chain state at onchainSize to the
// sealed state. This is the production one-seal-one-publish primitive; a
// publisher catching up over several seals chains one proof per seal
// (BuildConsistencyProofChain).
func BuildCheckpointProof(
	ctx context.Context, reader massifs.ObjectReader, onchainSize uint64, massifIndex uint32,
) (ConsistencyProof, SealedState, error) {
	sealed, err := ReadSealedState(ctx, reader, massifIndex)
	if err != nil {
		return ConsistencyProof{}, SealedState{}, err
	}
	mc, err := massifs.GetMassifContext(ctx, reader, massifIndex)
	if err != nil {
		return ConsistencyProof{}, SealedState{}, fmt.Errorf("read massif %d: %w", massifIndex, err)
	}
	proof, err := BuildConsistencyProof(&mc, onchainSize, sealed.MMRSize)
	if err != nil {
		return ConsistencyProof{}, SealedState{}, err
	}
	return proof, sealed, nil
}
