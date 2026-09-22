package publishproof

import (
	"math/big"
	"testing"

	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// The relay artefact a catch-up publish is built from is a checkpoint receipt
// in its own right: the head seal's signature over the whole chain. This
// walks the production path for a three-seal catch-up — read the head
// checkpoint, relay the chain, re-encode it as one receipt, and derive the
// calldata from that object — and requires the object and the calldata to say
// the same thing, and a third party with only the log's public key to verify
// the object from the state the contract itself starts at (ADR-0066 D5.4).
func TestChainReceiptCalldataRoundTrip(t *testing.T) {
	ctx := t.Context()
	logID := mustHex(t, "3132333435363738393a3b3c3d3e3f40")
	sealer := newFixtureSealer(t)
	reader, sealed, oracle := sealedMultiMassifLog(t, logID, sealer, 3)

	cp, err := massifs.GetCheckpoint(ctx, reader, 2)
	require.NoError(t, err)
	head, err := DecodeCheckpointReceipt(cp.Raw)
	require.NoError(t, err)
	require.Len(t, head.ConsistencyProofs, 1, "a sealed step carries exactly its own proof")

	// Catch up from an unanchored log: three sealed steps, one publish.
	chain, err := BuildEmbeddedProofChain(ctx, reader, 0, 2, head.ConsistencyProofs)
	require.NoError(t, err)
	require.Len(t, chain, 3)

	chainReceipt, err := EncodeChainReceipt(cp.Raw, chain)
	require.NoError(t, err)
	relayed, err := DecodeCheckpointReceipt(chainReceipt)
	require.NoError(t, err)
	require.Equal(t, chain, relayed.ConsistencyProofs, "the chain survives the round trip in order")
	require.Equal(t, head.ProtectedHeader, relayed.ProtectedHeader, "nothing signed is rebuilt")
	require.Equal(t, head.Signature, relayed.Signature)
	require.Equal(t, head.DelegationProof, relayed.DelegationProof)
	require.NoError(t, CheckSignedSize(relayed))

	// The calldata carries exactly what the object says, and nothing else:
	// unpacking the submission reproduces the decoded receipt.
	calldata, err := EncodePublishCheckpoint(
		relayed,
		InclusionProof{Index: 0, Path: [][32]byte{}},
		[8]byte{},
		PublishGrant{Grant: big.NewInt(1), Request: big.NewInt(1), GrantData: []byte{}},
	)
	require.NoError(t, err)
	submitted, _, _, _, err := DecodePublishCheckpoint(calldata)
	require.NoError(t, err)
	require.Equal(t, relayed, submitted)
	require.Equal(t, chain, submitted.ConsistencyProofs)

	// The pre-signed peak receipts the sealer attached are carried over, so
	// the relay object is the head receipt with its chain extended rather
	// than a lossy copy of it.
	headProfile, err := massifs.DecodeCheckpointReceipt(cp.Raw)
	require.NoError(t, err)
	relayedProfile, err := massifs.DecodeCheckpointReceipt(chainReceipt)
	require.NoError(t, err)
	require.NotEmpty(t, headProfile.PeakReceipts)
	require.Equal(t, headProfile.PeakReceipts, relayedProfile.PeakReceipts)

	// Third-party verification: fold the chain from the bootstrap state the
	// contract starts a log at, and check the head signature over the
	// accumulator the fold reaches.
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, &sealer.key.PublicKey)
	require.NoError(t, err)
	accumulator, err := massifs.VerifyCheckpointReceiptFromState(
		0, [][]byte{}, &relayedProfile, verifier)
	require.NoError(t, err)
	require.Equal(t, peaks32(t, oracle, sealed[2]), toBytes32Slice(accumulator))
}

// A chain whose links do not join is refused before it is encoded: the
// intermediate sizes carry no signature, so a gap would present two unrelated
// extensions as one catch-up. The error is the sentinel the go-merklelog
// verifier and the contract reject the same chain with.
func TestChainReceiptRejectsABrokenChain(t *testing.T) {
	ctx := t.Context()
	logID := mustHex(t, "4142434445464748494a4b4c4d4e4f50")
	reader, _, _ := sealedMultiMassifLog(t, logID, newFixtureSealer(t), 3)

	cp, err := massifs.GetCheckpoint(ctx, reader, 2)
	require.NoError(t, err)
	head, err := DecodeCheckpointReceipt(cp.Raw)
	require.NoError(t, err)
	chain, err := BuildEmbeddedProofChain(ctx, reader, 0, 2, head.ConsistencyProofs)
	require.NoError(t, err)
	require.Len(t, chain, 3)

	gapped := append([]ConsistencyProof(nil), chain...)
	gapped[1].TreeSize1++
	_, err = EncodeChainReceipt(cp.Raw, gapped)
	require.ErrorIs(t, err, massifs.ErrProofChainNotContiguous)

	// Dropping a link leaves a hole the same way.
	missing := []ConsistencyProof{chain[0], chain[2]}
	_, err = EncodeChainReceipt(cp.Raw, missing)
	require.ErrorIs(t, err, massifs.ErrProofChainNotContiguous)

	// A receipt proves something or it is not a receipt of consistency.
	_, err = EncodeChainReceipt(cp.Raw, nil)
	require.ErrorIs(t, err, massifs.ErrProofChainEmpty)
}

// ARB105-F1: a chain that stops short of the size the head signs must not
// encode. Only the last link's tree-size-2 is checked against the head's
// signed tree-size-2 - stopping early would produce a receipt whose
// accumulator and declared size disagree, caught only later by
// CheckSignedSize (or on-chain).
func TestChainReceiptRejectsChainShortOfSignedSize(t *testing.T) {
	ctx := t.Context()
	logID := mustHex(t, "3132333435363738393a3b3c3d3e3f40")
	reader, sealed, _ := sealedMultiMassifLog(t, logID, newFixtureSealer(t), 3)
	require.Len(t, sealed, 3)

	cp, err := massifs.GetCheckpoint(ctx, reader, 2)
	require.NoError(t, err)
	head, err := DecodeCheckpointReceipt(cp.Raw)
	require.NoError(t, err)
	chain, err := BuildEmbeddedProofChain(ctx, reader, 0, 2, head.ConsistencyProofs)
	require.NoError(t, err)
	require.Len(t, chain, 3)

	// Truncated to the first two links: ends at sealed[1], head signs sealed[2].
	short := chain[:2]
	_, err = EncodeChainReceipt(cp.Raw, short)
	require.ErrorIs(t, err, ErrSignedSizeMismatch)
}

// ARB105-F2: a zero-length link satisfies contiguity (it starts where the
// previous link ends) but proves nothing at that step; the univocity
// contract rejects any link whose tree-size-2 does not exceed its
// tree-size-1 (InvalidConsistencyProof), so it must be rejected here too,
// both directly and through EncodeChainReceipt.
func TestChainReceiptRejectsZeroLengthLink(t *testing.T) {
	ctx := t.Context()
	logID := mustHex(t, "3132333435363738393a3b3c3d3e3f40")
	reader, _, _ := sealedMultiMassifLog(t, logID, newFixtureSealer(t), 3)

	cp, err := massifs.GetCheckpoint(ctx, reader, 2)
	require.NoError(t, err)
	head, err := DecodeCheckpointReceipt(cp.Raw)
	require.NoError(t, err)
	chain, err := BuildEmbeddedProofChain(ctx, reader, 0, 2, head.ConsistencyProofs)
	require.NoError(t, err)
	require.Len(t, chain, 3)

	// Insert a zero-length link between the first and second links:
	// [0->7, 7->7, 7->15, 15->22].
	zeroLength := ConsistencyProof{
		TreeSize1:  chain[0].TreeSize2,
		TreeSize2:  chain[0].TreeSize2,
		Paths:      [][][32]byte{},
		RightPeaks: [][32]byte{},
	}
	withZeroLink := []ConsistencyProof{chain[0], zeroLength, chain[1], chain[2]}

	err = CheckProofChainContiguous(withZeroLink)
	require.ErrorIs(t, err, massifs.ErrConsistencyProofCheck)
	require.ErrorIs(t, err, mmr.ErrSizesNotIncreasing)

	_, err = EncodeChainReceipt(cp.Raw, withZeroLink)
	require.ErrorIs(t, err, massifs.ErrConsistencyProofCheck)
	require.ErrorIs(t, err, mmr.ErrSizesNotIncreasing)
}
