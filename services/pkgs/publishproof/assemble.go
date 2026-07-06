package publishproof

import (
	"context"
	"errors"
	"fmt"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// ErrAlreadyAnchored indicates the on-chain state already covers the sealed
// checkpoint (natural idempotency under permissionless concurrency: another
// publisher won the race, or the seal was published earlier).
var ErrAlreadyAnchored = errors.New("checkpoint already anchored on-chain")

// ErrOwnerNotAnchored indicates the grant's owner log has no on-chain state
// covering the grant leaf yet, so the grant inclusion proof cannot verify.
// The owner log must be published first (root-first ordering).
var ErrOwnerNotAnchored = errors.New("owner log not anchored over the grant leaf")

// AssemblePublish builds the publishCheckpoint calldata for the checkpoint
// sealed at massifIndex of logID, entirely from public objects (plan-2607-02
// slice 2): the v3 checkpoint receipt supplies the signature, protected
// header, and delegation proof; the stored grant transparent statement
// supplies the PublishGrant tuple and idtimestamp; the owner log's massif
// supplies the grant leaf position and inclusion proof against the owner's
// on-chain accumulator.
//
// The consistency proof is the checkpoint's own when the on-chain size
// matches its tree-size-1, and is otherwise rebuilt from the massif so a
// lagging on-chain state catches up in one publish (the signature covers only
// the final accumulator, so intermediate proofs need no signatures).
//
// r is the forest root from ResolveForestContract; targetOnchain and
// ownerOnchain are current logState reads from the resolved contract. owner
// is the owner log's object reader (the same reader as target when the grant
// is self-owned). The grant leaf is located across the owner log's massifs
// (FindGrantLeafMMRIndex) and its inclusion proof is read through a
// boundary-crossing node getter, so multi-massif authority logs are supported.
func AssemblePublish(
	ctx context.Context,
	grants ObjectGetter,
	r, logID logid.UUID,
	target massifs.ObjectReader, massifIndex uint32,
	owner massifs.ObjectReader,
	targetOnchain, ownerOnchain LogState,
) ([]byte, SealedState, error) {
	sg, err := ReadStoredGrant(ctx, grants, r, logID)
	if err != nil {
		return nil, SealedState{}, err
	}

	cp, err := massifs.GetCheckpoint(ctx, target, massifIndex)
	if err != nil {
		return nil, SealedState{}, fmt.Errorf("read checkpoint %d: %w", massifIndex, err)
	}
	receipt, err := DecodeCheckpointReceipt(cp.Raw)
	if err != nil {
		return nil, SealedState{}, fmt.Errorf("decode checkpoint %d: %w", massifIndex, err)
	}
	sealed, err := ReadSealedState(ctx, target, massifIndex)
	if err != nil {
		return nil, SealedState{}, err
	}
	if targetOnchain.Size >= sealed.MMRSize {
		return nil, SealedState{}, fmt.Errorf(
			"%w: on-chain size %d >= sealed size %d",
			ErrAlreadyAnchored, targetOnchain.Size, sealed.MMRSize)
	}

	// Catch-up: chain the pending checkpoints' own embedded per-seal proofs from
	// the on-chain size up to this seal. Each checkpoint object carries exactly
	// its (sealed(K-1) -> sealed(K)) link; the contract's
	// verifyConsistencyProofChain links them from the on-chain accumulator. This
	// relays the sealer's already-computed proofs — no massif node data is read
	// for the earlier massifs, and multi-massif catch-up needs no spanning reader.
	//
	// Invariant: on-chain size is always a sealed boundary (publishCheckpoint sets
	// log.size = the final proof's treeSize2, a checkpoint's sealed size), so the
	// chain always starts at some embedded proof's treeSize1.
	chain, err := BuildEmbeddedProofChain(ctx, target, targetOnchain.Size, massifIndex, receipt.ConsistencyProofs)
	if err != nil {
		return nil, SealedState{}, fmt.Errorf("build catch-up proof chain: %w", err)
	}
	if last := chain[len(chain)-1]; last.TreeSize2 != sealed.MMRSize {
		return nil, SealedState{}, fmt.Errorf(
			"head proof treeSize2 %d != sealed size %d", last.TreeSize2, sealed.MMRSize)
	}
	receipt.ConsistencyProofs = chain

	inclusion := InclusionProof{Index: 0, Path: [][32]byte{}}
	bootstrap := logID == r && targetOnchain.Size == 0 && ownerOnchain.Size == 0
	if !bootstrap {
		if ownerOnchain.Size == 0 {
			return nil, SealedState{}, fmt.Errorf(
				"%w: owner %s has no on-chain state", ErrOwnerNotAnchored, sg.OwnerLogID)
		}
		leaf, err := sg.LeafCommitment()
		if err != nil {
			return nil, SealedState{}, fmt.Errorf("grant leaf commitment: %w", err)
		}
		nodeIndex, err := FindGrantLeafMMRIndex(ctx, owner, ownerOnchain.Size, sg.IDTimestampBe, leaf)
		if errors.Is(err, ErrGrantLeafNotFound) {
			return nil, SealedState{}, fmt.Errorf(
				"%w: grant leaf for %s not within owner on-chain size %d: %v",
				ErrOwnerNotAnchored, logID, ownerOnchain.Size, err)
		}
		if err != nil {
			return nil, SealedState{}, err
		}
		// The grant leaf's inclusion path can cross massif boundaries, so read
		// nodes through a getter that routes each node to its owning massif.
		ownerHead, err := owner.HeadIndex(ctx, massifstorage.ObjectMassifData)
		if err != nil {
			return nil, SealedState{}, fmt.Errorf("owner log head massif: %w", err)
		}
		ownerMC, err := massifs.GetMassifContext(ctx, owner, ownerHead)
		if err != nil {
			return nil, SealedState{}, fmt.Errorf("read owner massif %d: %w", ownerHead, err)
		}
		nodes := newOwnerNodeGetter(ctx, owner, ownerMC.Start.MassifHeight)
		inclusion, err = BuildInclusionProof(nodes, ownerOnchain.Size, nodeIndex)
		if err != nil {
			return nil, SealedState{}, fmt.Errorf("grant inclusion proof: %w", err)
		}
		if err := verifyGrantInclusion(leaf, inclusion, ownerOnchain.Accumulator); err != nil {
			return nil, SealedState{}, fmt.Errorf("grant inclusion self-check: %w", err)
		}
	}

	calldata, err := EncodePublishCheckpoint(receipt, inclusion, sg.IDTimestampBe, sg.Grant)
	if err != nil {
		return nil, SealedState{}, fmt.Errorf("encode publishCheckpoint: %w", err)
	}
	return calldata, sealed, nil
}

// maxProofChainSteps bounds the catch-up walk (defensive against a corrupt or
// far-behind on-chain size). A publisher this far behind should reconcile.
const maxProofChainSteps = 4096

// BuildEmbeddedProofChain assembles the consistency-proof chain from the on-chain
// size up to the head checkpoint by RELAYING each pending checkpoint's own
// embedded per-seal proof — no massif node data is read. Each checkpoint object
// carries exactly its (sealed(K-1) -> sealed(K)) link, so the publisher walks
// from the head massif downward, reading one checkpoint object per step, until a
// link starts at the on-chain size; the contract's verifyConsistencyProofChain
// links them from the on-chain accumulator up to the head seal.
//
// headProofs is the head checkpoint's already-decoded embedded proof. The
// returned chain is ascending (oldest link first). A one-massif catch-up returns
// immediately with the single head link and reads nothing extra.
func BuildEmbeddedProofChain(
	ctx context.Context, reader massifs.ObjectReader,
	onchainSize uint64, headMassifIndex uint32, headProofs []ConsistencyProof,
) ([]ConsistencyProof, error) {
	chain := make([]ConsistencyProof, 0, 8)
	cur := headProofs
	k := headMassifIndex
	for steps := 0; ; steps++ {
		if steps > maxProofChainSteps {
			return nil, fmt.Errorf(
				"proof chain exceeds %d steps catching up from on-chain size %d", maxProofChainSteps, onchainSize)
		}
		if len(cur) != 1 {
			return nil, fmt.Errorf("checkpoint %d carries %d embedded proofs, want exactly 1", k, len(cur))
		}
		p := cur[0]
		// Links must be contiguous: this step's TreeSize2 feeds the next's TreeSize1.
		if len(chain) > 0 && p.TreeSize2 != chain[0].TreeSize1 {
			return nil, fmt.Errorf(
				"checkpoint %d proof treeSize2 %d != next treeSize1 %d (non-contiguous)",
				k, p.TreeSize2, chain[0].TreeSize1)
		}
		chain = append([]ConsistencyProof{p}, chain...) // prepend -> ascending

		switch {
		case p.TreeSize1 == onchainSize:
			return chain, nil // reached the on-chain accumulator
		case p.TreeSize1 < onchainSize:
			return nil, fmt.Errorf(
				"checkpoint %d proof treeSize1 %d below on-chain size %d (non-contiguous)", k, p.TreeSize1, onchainSize)
		case k == 0:
			return nil, fmt.Errorf("reached genesis without reaching on-chain size %d", onchainSize)
		}

		k--
		cp, err := massifs.GetCheckpoint(ctx, reader, k)
		if err != nil {
			return nil, fmt.Errorf("read checkpoint %d: %w", k, err)
		}
		rec, err := DecodeCheckpointReceipt(cp.Raw)
		if err != nil {
			return nil, fmt.Errorf("decode checkpoint %d: %w", k, err)
		}
		cur = rec.ConsistencyProofs
	}
}
