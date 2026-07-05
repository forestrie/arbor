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
// is self-owned). The owner-side inclusion scan assumes the owner log's
// leaves are within its head massif (authority logs hold one leaf per grant;
// multi-massif authority logs are a documented follow-up).
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

	// Catch-up: rebuild the proof from the massif when the on-chain state
	// does not align with the seal's own proof.
	if len(receipt.ConsistencyProofs) != 1 ||
		receipt.ConsistencyProofs[0].TreeSize1 != targetOnchain.Size {
		proof, _, err := BuildCheckpointProof(ctx, target, targetOnchain.Size, massifIndex)
		if err != nil {
			return nil, SealedState{}, fmt.Errorf("rebuild catch-up proof: %w", err)
		}
		receipt.ConsistencyProofs = []ConsistencyProof{proof}
	}

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
