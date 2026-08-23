package publishproof

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Selector pinned from the v0.2.0 release artifact ABI (ADR-0008 adds
// bytes[] algData as the 6th DelegationProof component):
//
//	295e6ade publishCheckpoint((bytes,bytes,(uint64,uint64,bytes32[][],bytes32[])[],(bytes,bytes,uint64,uint64,bytes,bytes[])),(uint64,bytes32[]),bytes8,(bytes32,uint256,uint256,uint64,uint64,bytes32,bytes))
const publishCheckpointSelectorHex = "295e6ade"

// The FOR-314 spike pins the multi-seal composition a publisher must produce
// for on-chain size 0 -> 2: one proof per sealed step.
func TestEncodePublishCheckpointRoundTripsPinnedProofChain(t *testing.T) {
	leaf1 := bytes32FromLow(t, "11")
	leaf2 := bytes32FromLow(t, "22")

	receipt := ConsistencyReceipt{
		ProtectedHeader: mustHex(t, "a1013a00010106"),
		Signature:       make([]byte, 65),
		ConsistencyProofs: []ConsistencyProof{
			{TreeSize1: 0, TreeSize2: 1, Paths: [][][32]byte{}, RightPeaks: [][32]byte{leaf1}},
			{TreeSize1: 1, TreeSize2: 2, Paths: [][][32]byte{{leaf2}}, RightPeaks: [][32]byte{leaf2}},
		},
		// ABI bytes have no nil; an absent delegation is empty fields.
		// ES256/KS256 MUST carry an empty algData (ADR-0008 fail-closed).
		DelegationProof: DelegationProof{
			ProtectedHeader: []byte{},
			DelegationKey:   []byte{},
			Signature:       []byte{},
			AlgData:         [][]byte{},
		},
	}
	inclusion := InclusionProof{Index: 1, Path: [][32]byte{leaf1}}
	var idTimestamp [8]byte
	idTimestamp[7] = 0x01
	grant := PublishGrant{
		LogId:      bytes32FromLow(t, "000102030405060708090a0b0c0d0e0f"),
		Grant:      big.NewInt(1),
		Request:    new(big.Int).Lsh(big.NewInt(2), 224),
		MaxHeight:  1000,
		MinGrowth:  1,
		OwnerLogId: bytes32FromLow(t, "101112131415161718191a1b1c1d1e1f"),
		GrantData:  mustHex(t, "abcd"),
	}

	calldata, err := EncodePublishCheckpoint(receipt, inclusion, idTimestamp, grant)
	require.NoError(t, err)
	require.Equal(t, publishCheckpointSelectorHex, hex.EncodeToString(calldata[:4]))

	gotReceipt, gotInclusion, gotIDTimestamp, gotGrant, err := DecodePublishCheckpoint(calldata)
	require.NoError(t, err)
	require.Equal(t, receipt, gotReceipt)
	require.Equal(t, inclusion, gotInclusion)
	require.Equal(t, idTimestamp, gotIDTimestamp)
	require.Equal(t, grant.LogId, gotGrant.LogId)
	require.Equal(t, 0, grant.Grant.Cmp(gotGrant.Grant))
	require.Equal(t, 0, grant.Request.Cmp(gotGrant.Request))
	require.Equal(t, grant.MaxHeight, gotGrant.MaxHeight)
	require.Equal(t, grant.MinGrowth, gotGrant.MinGrowth)
	require.Equal(t, grant.OwnerLogId, gotGrant.OwnerLogId)
	require.Equal(t, grant.GrantData, gotGrant.GrantData)
}
