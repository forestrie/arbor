package publishproof

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/stretchr/testify/require"
)

// storedGrantFor encodes and stores the transparent statement for a grant so
// the assembly reads it back exactly as the publisher would in production.
func storedGrantFor(
	t *testing.T, objects *memObjectClient, r, subject logid.UUID,
	class string, flags uint64, idts [8]byte, grantData []byte,
) {
	t.Helper()
	flagBytes := make([]byte, 8)
	for i := 7; i >= 0 && flags > 0; i-- {
		flagBytes[i] = byte(flags)
		flags >>= 8
	}
	var idtsArg []byte
	if idts != ([8]byte{}) {
		idtsArg = idts[:]
	}
	body := encodeStoredGrant(t, storedGrantOpts{
		logID: subject, ownerLogID: r, flags: flagBytes,
		maxHeight: 1000, minGrowth: 0, grantData: grantData,
		idts: idtsArg, tag18: true,
	})
	objects.objects[grantKeyForTest(r, subject, class)] = body
}

// TestAssemblePublishFromStoredGrants is the slice-2 assembly proof: the
// publishCheckpoint calldata for bootstrap, authority extend, first child-log
// checkpoint, and delegated extend is assembled entirely from public objects —
// the v3 checkpoint (signature, proofs, delegation), the stored grant
// transparent statements (PublishGrant, idtimestamp), and the owner-log
// massif (grant leaf position, inclusion proof). No hand-built grant material.
func TestAssemblePublishFromStoredGrants(t *testing.T) {
	ctx := t.Context()
	client := startAnvil(t)

	root := newFixtureSealer(t)
	delegate := newFixtureSealer(t)
	rootPub := make([]byte, 64)
	root.key.PublicKey.X.FillBytes(rootPub[:32])
	root.key.PublicKey.Y.FillBytes(rootPub[32:])
	harness := deployUnivocityKey(t, client, algES256, rootPub)

	rootUUID := testLogID(t, "60616263-6465-4667-a869-6a6b6c6d6e6f")
	targetUUID := testLogID(t, "70717273-7475-4677-a879-7a7b7c7d7e7f")
	rootLogID := rootUUID[:]
	targetLogID := targetUUID[:]
	rootLogId32 := bytes32FromLow(t, hex.EncodeToString(rootLogID))
	targetLogId32 := bytes32FromLow(t, hex.EncodeToString(targetLogID))

	objects := newMemObjectClient()
	grants := mapGetter(objects.objects)

	// Stored grants: the root self-grant uses the zero idtimestamp (the live
	// convention observed on forest-dev-5); the data-log grant is sequenced.
	idt1 := idTimestamp(2)
	storedGrantFor(t, objects, rootUUID, rootUUID, "auth-log",
		gfCreate|gfExtend|gfAuthLog, [8]byte{}, rootPub)
	storedGrantFor(t, objects, rootUUID, targetUUID, "data-log",
		gfCreate|gfExtend|gfDataLog, idt1, rootPub)

	rootGrant, err := ReadStoredGrant(ctx, grants, rootUUID, rootUUID)
	require.NoError(t, err)
	leafG0, err := rootGrant.LeafCommitment()
	require.NoError(t, err)
	targetGrant, err := ReadStoredGrant(ctx, grants, rootUUID, targetUUID)
	require.NoError(t, err)
	leafGT, err := targetGrant.LeafCommitment()
	require.NoError(t, err)

	// Authority log fixture: grant leaves, root-sealed.
	authority := newFixtureLog(t, objects, rootLogID, root)
	require.Equal(t, uint64(1), authority.addLeaves(leafG0))
	authority.commitAndSeal()

	zeroState := LogState{Accumulator: [][32]byte{}, Size: 0}

	// Bootstrap the root log: no on-chain state on either side.
	calldata, sealed, err := AssemblePublish(ctx, grants, rootUUID, rootUUID,
		authority.reader(), 0, authority.reader(), zeroState, zeroState)
	require.NoError(t, err)
	require.Equal(t, uint64(1), sealed.MMRSize)
	harness.publishCheckpoint(calldata, "assembled bootstrap (stored grant)")

	rootState, err := ReadLogState(ctx, client, harness.contract, rootLogId32)
	require.NoError(t, err)
	require.Equal(t, uint64(1), rootState.Size)

	// Extend the authority log with the target grant leaf.
	require.Equal(t, uint64(3), authority.addLeaves(leafGT))
	authority.commitAndSeal()

	calldata, sealed, err = AssemblePublish(ctx, grants, rootUUID, rootUUID,
		authority.reader(), 0, authority.reader(), rootState, rootState)
	require.NoError(t, err)
	require.Equal(t, uint64(3), sealed.MMRSize)
	harness.publishCheckpoint(calldata, "assembled authority extend (stored grant)")

	rootState, err = ReadLogState(ctx, client, harness.contract, rootLogId32)
	require.NoError(t, err)
	require.Equal(t, uint64(3), rootState.Size)

	// Target log: sealed by the delegate with the on-chain delegation proof
	// riding each checkpoint (the assembly passes it through untouched).
	dx := make([]byte, 32)
	dy := make([]byte, 32)
	delegate.key.PublicKey.X.FillBytes(dx)
	delegate.key.PublicKey.Y.FillBytes(dy)
	delegatedKey, err := delegationcert.NewDelegatedCoseKey(delegationcert.Secp256r1, dx, dy)
	require.NoError(t, err)
	tbs, err := delegationcert.BuildOnchainDelegationToBeSigned(
		hex.EncodeToString(targetLogID), 0, uint64(1)<<40, delegatedKey)
	require.NoError(t, err)
	digest := sha256.Sum256(tbs.SigStructure)
	sr, ss, err := ecdsa.Sign(rand.Reader, &root.key, digest[:])
	require.NoError(t, err)
	rawSig := make([]byte, 64)
	sr.FillBytes(rawSig[:32])
	ss.FillBytes(rawSig[32:])
	onchain, err := delegationcert.AssembleOnchainDelegationProof(tbs, 0, uint64(1)<<40, rawSig)
	require.NoError(t, err)

	target := newFixtureLog(t, objects, targetLogID, delegate)
	target.onchainProof = onchain

	var dataLeaves [][32]byte
	for i := range 5 {
		dataLeaves = append(dataLeaves, bytes32FromLow(t, fmt.Sprintf("%02x", 0xf0+i)))
	}

	// Owner not anchored: assembling against a zero owner state must refuse.
	firstSize := target.addLeaves(dataLeaves[:3]...)
	target.commitAndSeal()
	_, _, err = AssemblePublish(ctx, grants, rootUUID, targetUUID,
		target.reader(), 0, authority.reader(), zeroState, zeroState)
	require.ErrorIs(t, err, ErrOwnerNotAnchored)

	// First target checkpoint: grant leaf found in the authority massif and
	// proven against the owner's on-chain accumulator.
	calldata, sealed, err = AssemblePublish(ctx, grants, rootUUID, targetUUID,
		target.reader(), 0, authority.reader(), zeroState, rootState)
	require.NoError(t, err)
	require.Equal(t, firstSize, sealed.MMRSize)
	harness.publishCheckpoint(calldata, "assembled first target checkpoint (stored grant)")

	targetState, err := ReadLogState(ctx, client, harness.contract, targetLogId32)
	require.NoError(t, err)
	require.Equal(t, firstSize, targetState.Size)
	require.Equal(t, sealed.Accumulator, targetState.Accumulator)

	// Already anchored: re-assembling the same seal must refuse.
	_, _, err = AssemblePublish(ctx, grants, rootUUID, targetUUID,
		target.reader(), 0, authority.reader(), targetState, rootState)
	require.ErrorIs(t, err, ErrAlreadyAnchored)

	// Delegated extend.
	extendSize := target.addLeaves(dataLeaves[3:]...)
	target.commitAndSeal()
	calldata, sealed, err = AssemblePublish(ctx, grants, rootUUID, targetUUID,
		target.reader(), 0, authority.reader(), targetState, rootState)
	require.NoError(t, err)
	require.Equal(t, extendSize, sealed.MMRSize)
	harness.publishCheckpoint(calldata, "assembled delegated target extend (stored grant)")

	targetState, err = ReadLogState(ctx, client, harness.contract, targetLogId32)
	require.NoError(t, err)
	require.Equal(t, extendSize, targetState.Size)
	require.Equal(t, sealed.Accumulator, targetState.Accumulator)
}
