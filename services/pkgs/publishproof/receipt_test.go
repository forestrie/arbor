package publishproof

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestConsistencyProofRoundTrip(t *testing.T) {
	leaf1 := bytes32FromLow(t, "11")
	leaf2 := bytes32FromLow(t, "22")
	proof := ConsistencyProof{
		TreeSize1:  1,
		TreeSize2:  2,
		Paths:      [][][32]byte{{leaf2}},
		RightPeaks: [][32]byte{leaf2, leaf1},
	}

	encoded, err := EncodeConsistencyProof(proof)
	require.NoError(t, err)
	got, err := DecodeConsistencyProof(encoded)
	require.NoError(t, err)
	require.Equal(t, proof, got)
}

// The degenerate first-checkpoint proof (treeSize1 == 0, empty paths) must
// round-trip too — empty Paths encodes as a zero-length CBOR array.
func TestConsistencyProofRoundTripFirstCheckpoint(t *testing.T) {
	leaf1 := bytes32FromLow(t, "aa")
	proof := ConsistencyProof{
		TreeSize1:  0,
		TreeSize2:  1,
		Paths:      [][][32]byte{},
		RightPeaks: [][32]byte{leaf1},
	}

	encoded, err := EncodeConsistencyProof(proof)
	require.NoError(t, err)
	got, err := DecodeConsistencyProof(encoded)
	require.NoError(t, err)
	require.Equal(t, proof, got)
}

func TestCheckpointReceiptRoundTrip(t *testing.T) {
	leaf1 := bytes32FromLow(t, "11")
	proof := ConsistencyProof{
		TreeSize1:  0,
		TreeSize2:  1,
		Paths:      [][][32]byte{},
		RightPeaks: [][32]byte{leaf1},
	}
	protected := mustHex(t, "a1013a00010106")
	signature := make([]byte, 65)
	signature[0] = 0xAB

	encoded, err := EncodeCheckpointReceipt(protected, proof, signature)
	require.NoError(t, err)

	got, err := DecodeCheckpointReceipt(encoded)
	require.NoError(t, err)
	require.Equal(t, protected, got.ProtectedHeader)
	require.Equal(t, signature, got.Signature)
	require.Len(t, got.ConsistencyProofs, 1)
	require.Equal(t, proof, got.ConsistencyProofs[0])
	// Detached payload: nothing carried in the object itself.
	require.Equal(t, []byte{}, got.DelegationProof.Signature)
	// ES256/KS256 require an empty algData (ADR-0008 fail-closed).
	require.Equal(t, [][]byte{}, got.DelegationProof.AlgData)
}

// A decoded checkpoint receipt on the plain-signing (ES256/KS256) path must
// produce calldata with an EMPTY algData — the v0.2.0 contract reverts
// UnexpectedDelegationAlgData on any element — and survive the calldata
// round-trip unchanged.
func TestDecodedReceiptEncodesEmptyAlgData(t *testing.T) {
	leaf1 := bytes32FromLow(t, "11")
	proof := ConsistencyProof{
		TreeSize1:  0,
		TreeSize2:  1,
		Paths:      [][][32]byte{},
		RightPeaks: [][32]byte{leaf1},
	}
	encoded, err := EncodeCheckpointReceipt(mustHex(t, "a1013a00010106"), proof, make([]byte, 65))
	require.NoError(t, err)
	receipt, err := DecodeCheckpointReceipt(encoded)
	require.NoError(t, err)

	calldata, err := EncodePublishCheckpoint(
		receipt,
		InclusionProof{Index: 0, Path: [][32]byte{}},
		[8]byte{},
		PublishGrant{
			Grant:     big.NewInt(1),
			Request:   big.NewInt(1),
			GrantData: []byte{},
		},
	)
	require.NoError(t, err)

	gotReceipt, _, _, _, err := DecodePublishCheckpoint(calldata)
	require.NoError(t, err)
	require.Equal(t, [][]byte{}, gotReceipt.DelegationProof.AlgData)
	require.Equal(t, receipt, gotReceipt)
}

// A checkpoint whose embedded OnchainDelegationProof carries the 3-element
// WebAuthn algData (ADR-0063) must lift it into the calldata DelegationProof
// and survive the calldata round-trip; a proof that omits the field must
// still normalize to the empty algData plain algs require.
func TestDecodedReceiptLiftsWebauthnAlgData(t *testing.T) {
	sealer := newFixtureSealer(t)

	proof := ConsistencyProof{
		TreeSize1:  0,
		TreeSize2:  1,
		Paths:      [][][32]byte{},
		RightPeaks: [][32]byte{bytes32FromLow(t, "11")},
	}
	authenticatorData := make([]byte, 37)
	authenticatorData[32] = 0x05 // UP | UV
	algData := [][]byte{
		authenticatorData,
		[]byte(`{"type":"webauthn.get","challenge":"x"}`),
		make([]byte, 16),
	}
	onchain := &delegationcert.OnchainDelegationProof{
		ProtectedHeader: mustHex(t, "a1013a00010107"), // {1: -65800}
		DelegationKey:   make([]byte, 64),
		MMRStart:        0,
		MMREnd:          1 << 40,
		Signature:       make([]byte, 64),
		AlgData:         algData,
	}
	raw, err := cbor.Marshal(onchain)
	require.NoError(t, err)

	encoded, err := massifs.SignCheckpointReceipt(
		sealer.coseSigner, toProfileProof(proof), [][]byte{make([]byte, 32)},
		massifs.WithUnprotectedExtras(
			map[int64]cbor.RawMessage{massifs.SealDelegationProofLabel: raw}))
	require.NoError(t, err)

	receipt, err := DecodeCheckpointReceipt(encoded)
	require.NoError(t, err)
	require.Equal(t, algData, receipt.DelegationProof.AlgData)

	calldata, err := EncodePublishCheckpoint(
		receipt,
		InclusionProof{Index: 0, Path: [][32]byte{}},
		[8]byte{},
		PublishGrant{Grant: big.NewInt(1), Request: big.NewInt(1), GrantData: []byte{}},
	)
	require.NoError(t, err)
	gotReceipt, _, _, _, err := DecodePublishCheckpoint(calldata)
	require.NoError(t, err)
	require.Equal(t, receipt, gotReceipt)

	// Legacy 5-field proof (no algData key): lift normalizes to empty.
	onchain.AlgData = nil
	raw, err = cbor.Marshal(onchain)
	require.NoError(t, err)
	encoded, err = massifs.SignCheckpointReceipt(
		sealer.coseSigner, toProfileProof(proof), [][]byte{make([]byte, 32)},
		massifs.WithUnprotectedExtras(
			map[int64]cbor.RawMessage{massifs.SealDelegationProofLabel: raw}))
	require.NoError(t, err)
	receipt, err = DecodeCheckpointReceipt(encoded)
	require.NoError(t, err)
	require.Equal(t, [][]byte{}, receipt.DelegationProof.AlgData)
}

// The vertical slice: a format-v3 checkpoint object encoded by publishproof
// (standing in for the sealer) decodes to calldata that publishes on-chain.
func TestCheckpointReceiptDecodesToPublishableCalldata(t *testing.T) {
	ctx := t.Context()
	client := startAnvil(t)

	signerKey, err := crypto.HexToECDSA(anvilKey0Hex)
	require.NoError(t, err)
	signerAddr := crypto.PubkeyToAddress(signerKey.PublicKey)
	harness := deployUnivocity(t, client, signerAddr)

	rootLogID := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	rootLogId32 := bytes32FromLow(t, "000102030405060708090a0b0c0d0e0f")
	g0 := PublishGrant{
		LogId:      rootLogId32,
		Grant:      new(big.Int).SetUint64(gfCreate | gfExtend | gfAuthLog),
		Request:    gcAuthLog,
		MaxHeight:  1000,
		MinGrowth:  0,
		OwnerLogId: [32]byte{},
		GrantData:  signerAddr.Bytes(),
	}
	idt0 := idTimestamp(1)
	leafG0, err := g0.LeafCommitment(idt0)
	require.NoError(t, err)

	sealer := newFixtureSealer(t)
	objects := newMemObjectClient()
	authority := newFixtureLog(t, objects, rootLogID, sealer)
	require.Equal(t, uint64(1), authority.addLeaves(leafG0))
	authority.commitAndSeal()

	proof, sealed, err := BuildCheckpointProof(ctx, authority.reader(), 0, 0)
	require.NoError(t, err)
	signature := signReceiptKS256(t, signerKey, protectedKS256, sealed.Accumulator)

	// Encode the checkpoint object, then decode it as the publisher would.
	receiptBytes, err := EncodeCheckpointReceipt(protectedKS256, proof, signature)
	require.NoError(t, err)
	receipt, err := DecodeCheckpointReceipt(receiptBytes)
	require.NoError(t, err)

	calldata, err := EncodePublishCheckpoint(
		receipt, InclusionProof{Index: 0, Path: [][32]byte{}}, idt0, g0,
	)
	require.NoError(t, err)
	harness.publishCheckpoint(calldata, "publish from decoded v3 checkpoint receipt")

	state, err := ReadLogState(ctx, client, harness.contract, rootLogId32)
	require.NoError(t, err)
	require.Equal(t, uint64(1), state.Size)
}
