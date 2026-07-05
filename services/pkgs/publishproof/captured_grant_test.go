package publishproof

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/require"
)

// The canopy grant-flags wire encoding is load-bearing at the wire↔contract
// boundary and had never been exercised end-to-end (R1 / FOR-328): every prior
// fixture built PublishGrant.Grant from the contract constants (gfCreate = 1<<32)
// rather than from the 8 wire bytes canopy actually emits, so the byte position
// canopy chose was never fed to a real publishCheckpoint.
//
// These two byte layouts are the exact 8-byte auth-log create grant canopy emits
// (grant-flags.ts authLogBootstrapShapedFlags: create|extend + auth-log class):
//
//	fixed (FOR-328): byte 3 = 0x03, byte 7 = 0x01  -> uint256 g = 0x0000000300000001
//	buggy (pre-fix): byte 4 = 0x03, byte 7 = 0x01  -> uint256 g = 0x0000000003000001
//
// The contract reads g big-endian and requires (g & GF_CREATE) != 0 with
// GF_CREATE = 1<<32 (interfaces/constants.sol). Byte 3 lands create/extend on
// bits 32/33; byte 4 lands them on bits 24/25, so the buggy layout has GF_CREATE
// unset and the first checkpoint reverts GrantRequirement. The buggy value
// 0x03000001 is exactly the grant stored live on forest-dev-5.
var (
	capturedGrantWireFixed = []byte{0, 0, 0, 0x03, 0, 0, 0, 0x01}
	capturedGrantWireBuggy = []byte{0, 0, 0, 0, 0x03, 0, 0, 0x01}
)

// assembleCapturedBootstrap deploys a fresh univocity instance and assembles the
// bootstrap (first, create) publishCheckpoint calldata for a root self-grant
// whose stored transparent statement carries the given canopy wire flag bytes —
// read back through ReadStoredGrant and assembled through AssemblePublish exactly
// as the publisher does in production (no hand-built grant uint256). Returns the
// calldata, the resolved grant value the contract will test, the deployed
// harness, and the root logId.
func assembleCapturedBootstrap(t *testing.T, client *ethclient.Client, wireFlags []byte) ([]byte, *big.Int, *chainHarness, [32]byte) {
	t.Helper()
	ctx := t.Context()

	root := newFixtureSealer(t)
	rootPub := make([]byte, 64)
	root.key.PublicKey.X.FillBytes(rootPub[:32])
	root.key.PublicKey.Y.FillBytes(rootPub[32:])
	harness := deployUnivocityKey(t, client, algES256, rootPub)

	rootUUID := testLogID(t, "60616263-6465-4667-a869-6a6b6c6d6e6f")
	rootLogID := rootUUID[:]
	rootLogId32 := bytes32FromLow(t, hex.EncodeToString(rootLogID))

	objects := newMemObjectClient()
	grants := mapGetter(objects.objects)

	// Stored root self-grant with the exact canopy wire flag bytes (zero
	// idtimestamp, the live forest-dev-5 self-grant convention).
	body := encodeStoredGrant(t, storedGrantOpts{
		logID: rootUUID, ownerLogID: rootUUID, flags: wireFlags,
		maxHeight: 1000, minGrowth: 0, grantData: rootPub, tag18: true,
	})
	objects.objects[grantKeyForTest(rootUUID, rootUUID, "auth-log")] = body

	rootGrant, err := ReadStoredGrant(ctx, grants, rootUUID, rootUUID)
	require.NoError(t, err)
	rootContent, err := rootGrant.ContentHash()
	require.NoError(t, err)

	authority := newFixtureLog(t, objects, rootLogID, root)
	require.Equal(t, uint64(1), authority.addEntry(0, rootContent))
	authority.commitAndSeal()

	zeroState := LogState{Accumulator: [][32]byte{}, Size: 0}
	calldata, _, err := AssemblePublish(ctx, grants, rootUUID, rootUUID,
		authority.reader(), 0, authority.reader(), zeroState, zeroState)
	require.NoError(t, err)

	return calldata, rootGrant.Grant.Grant, harness, rootLogId32
}

// TestCapturedGrantWireEncodingPublish is the FOR-328 captured-grant vector: a
// byte-faithful canopy auth-log create grant, read from a stored transparent
// statement and assembled by publishproof, reaches publishCheckpoint. The fixed
// (byte-3) encoding the contract accepts; the pre-fix (byte-4) encoding — the
// value stored live on forest-dev-5 (0x03000001) — is rejected with GF_CREATE
// unset. Absent this vector, R1 went unnoticed because no test used the canopy
// wire shape.
func TestCapturedGrantWireEncodingPublish(t *testing.T) {
	ctx := t.Context()
	client := startAnvil(t)

	t.Run("byte-3 encoding: contract accepts and logState advances", func(t *testing.T) {
		calldata, g, harness, rootId32 := assembleCapturedBootstrap(t, client, capturedGrantWireFixed)

		// The resolved grant has GF_CREATE, GF_EXTEND and GF_AUTH_LOG set.
		require.Equal(t, new(big.Int).SetUint64(gfCreate|gfExtend|gfAuthLog), g)
		require.NotZero(t, new(big.Int).And(g, new(big.Int).SetUint64(gfCreate)).Sign(),
			"GF_CREATE must be set for a canopy create grant")

		harness.publishCheckpoint(calldata, "captured byte-3 auth-log create grant")
		st, err := ReadLogState(ctx, client, harness.contract, rootId32)
		require.NoError(t, err)
		require.Equal(t, uint64(1), st.Size)
	})

	t.Run("byte-4 encoding (live forest-dev-5 0x03000001): GrantRequirement revert", func(t *testing.T) {
		calldata, g, harness, _ := assembleCapturedBootstrap(t, client, capturedGrantWireBuggy)

		// Exactly the value stored live on forest-dev-5, with GF_CREATE unset —
		// the root cause of the FOR-328 revert.
		require.Equal(t, big.NewInt(0x03000001), g)
		require.Zero(t, new(big.Int).And(g, new(big.Int).SetUint64(gfCreate)).Sign(),
			"the buggy byte-4 layout leaves GF_CREATE unset")

		// The contract rejects the first checkpoint with
		// GrantRequirement(GF_CREATE|GF_AUTH_LOG, GC_AUTH_LOG), since
		// (g & GF_CREATE) == 0. eth_call surfaces the revert (with its ABI error
		// data) without mutating chain state.
		msg := ethereum.CallMsg{From: harness.from, To: &harness.contract, Data: calldata, Gas: 4_000_000}
		_, err := client.CallContract(ctx, msg, nil)
		require.Error(t, err, "byte-4 canopy grant must revert on the first checkpoint")

		// Assert it is specifically GrantRequirement, so a revert for any other
		// reason cannot make this vector pass.
		selector := hex.EncodeToString(crypto.Keccak256([]byte("GrantRequirement(uint256,uint256)"))[:4])
		revertData := revertErrorData(t, err)
		require.Truef(t, strings.HasPrefix(revertData, "0x"+selector),
			"revert must be GrantRequirement (selector %s); got %s", selector, revertData)
	})
}

// revertErrorData extracts the ABI-encoded revert data (0x-prefixed) from a
// go-ethereum eth_call error. The JSON-RPC error carries it via ErrorData().
func revertErrorData(t *testing.T, err error) string {
	t.Helper()
	type dataError interface{ ErrorData() interface{} }
	de, ok := err.(dataError)
	require.Truef(t, ok, "eth_call error carries no revert data: %v", err)
	return fmt.Sprintf("%v", de.ErrorData())
}
