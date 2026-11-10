package publishproof

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/stretchr/testify/require"
)

// The first checkpoint of a KS256-rooted log, published the way production
// publishes it. A log is anchored once its first checkpoint is on chain, so
// a KS256 log whose first checkpoint cannot publish never anchors.
//
// Production never signs a checkpoint with the KS256 root itself. The sealer
// signs every checkpoint with a standing P-256 delegate (ES256), and each
// checkpoint carries the on-chain delegation proof in which the log's own
// root authorises that delegate (protocol ADR-0050,
// https://github.com/forestrie/protocol/blob/main/decisions/adr-0050-delegation-in-advance.md).
// The contract checks the proof against the forest's bootstrap key for the
// root log, and against the create grant's grantData for a child's first
// checkpoint, which it then records as the child's rootKey. Every publish
// here goes through AssemblePublish, the publisher's path from public
// objects to calldata.

func TestKS256RootFirstCheckpointPublishes(t *testing.T) {
	f := newKS256Forest(t, "80818283-8485-4687-a889-8a8b8c8d8e8f")

	f.publishFirst(f.rootUUID, f.authority, "first checkpoint of a KS256 forest root")
	require.Equal(t, crypto.PubkeyToAddress(f.rootKey.PublicKey).Bytes(), f.rootKeyOf(f.rootUUID),
		"the root's recorded rootKey must be the bootstrap address")
}

func TestKS256EOAChildFirstCheckpointPublishesWithGrantDataAsRootKey(t *testing.T) {
	f := newKS256Forest(t, "90919293-9495-4697-a899-9a9b9c9d9e9f")
	f.publish(f.rootUUID, f.authority, "root bootstrap")

	// C: a child whose root is its own KS256 address, not R's.
	childKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	childAddr := crypto.PubkeyToAddress(childKey.PublicKey)
	childUUID := testLogID(t, "a0a1a2a3-a4a5-46a7-a8a9-aaabacadaeaf")
	f.grantChild(childUUID, childAddr.Bytes())

	child := f.openLog(childUUID, childKey)
	child.addEntry(f.nextIdtimestamp(), bytes32FromLow(t, "c0"))
	child.commitAndSeal()
	f.publishFirst(childUUID, child, "first checkpoint of a KS256 EOA child")
	require.Equal(t, childAddr.Bytes(), f.rootKeyOf(childUUID),
		"the child's recorded rootKey must be its grant's grantData")
}

// TestERC1271ChildFirstCheckpointPublishes covers a child rooted in a smart
// account, the way a Safe-rooted child is. The account here is a minimal
// ERC-1271 mock, not a Safe: what a Safe's owners sign (the Safe's own
// message hash over the digest the contract passes it) is the signer's
// concern, and the publisher relays the signature bytes untouched.
func TestERC1271ChildFirstCheckpointPublishes(t *testing.T) {
	f := newKS256Forest(t, "b0b1b2b3-b4b5-46b7-a8b9-babbbcbdbebf")
	f.publish(f.rootUUID, f.authority, "root bootstrap")

	// S: a child whose root is a smart account. The account's owner signs,
	// and the contract asks the account (ERC-1271) whether the signature
	// stands; recovering the owner's address would not match grantData.
	ownerKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	wallet := f.chain.deployERC1271Wallet(crypto.PubkeyToAddress(ownerKey.PublicKey))
	safeUUID := testLogID(t, "c0c1c2c3-c4c5-46c7-a8c9-cacbcccdcecf")
	f.grantChild(safeUUID, wallet.Bytes())

	safe := f.openLog(safeUUID, ownerKey)
	safe.addEntry(f.nextIdtimestamp(), bytes32FromLow(t, "c0"))
	safe.commitAndSeal()
	f.publishFirst(safeUUID, safe, "first checkpoint of an ERC-1271 child")
	require.Equal(t, wallet.Bytes(), f.rootKeyOf(safeUUID),
		"the ERC-1271 child's recorded rootKey must be the account's address")
}

// laneUnivocityRelease is the univocity release Lane A deploys for each run
// (the lane's hydrated release manifest, univocity.ks256.releaseTag), so
// these tests exercise the contract the lane runs.
const laneUnivocityRelease = "v0.3.0"

// ks256Forest is a forest on anvil whose root R is a KS256 address. Every
// log in it is owned by R and sealed by one standing P-256 delegate.
type ks256Forest struct {
	t        *testing.T
	client   *ethclient.Client
	chain    *chainHarness
	objects  *memObjectClient
	grants   mapGetter
	leaves   *GrantLeafIndex
	delegate *fixtureSealer

	rootKey   *ecdsa.PrivateKey
	rootUUID  logid.UUID
	authority *fixtureLog
	idts      uint64
}

// newKS256Forest deploys a univocity instance bootstrapped to a fresh KS256
// key R, stores R's auth-log self-grant (grantData = R's address) and opens
// R's authority log with the self-grant as its first entry, sealed under a
// delegation R signed.
func newKS256Forest(t *testing.T, rootUUID string) *ks256Forest {
	t.Helper()
	client := startAnvil(t)
	rootKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	rootAddr := crypto.PubkeyToAddress(rootKey.PublicKey)

	objects := newMemObjectClient()
	f := &ks256Forest{
		t:        t,
		client:   client,
		chain:    deployUnivocityRelease(t, client, laneUnivocityRelease, algKS256, rootAddr.Bytes()),
		objects:  objects,
		grants:   mapGetter(objects.objects),
		leaves:   NewGrantLeafIndex(),
		delegate: newFixtureSealer(t),
		rootKey:  rootKey,
		rootUUID: testLogID(t, rootUUID),
	}

	// The root self-grant carries the zero idtimestamp, the convention for a
	// forest's bootstrap grant (see TestAssemblePublishFromStoredGrants).
	storedGrantFor(t, objects, f.rootUUID, f.rootUUID, "auth-log",
		gfCreate|gfExtend|gfAuthLog, [8]byte{}, rootAddr.Bytes())
	f.authority = f.openLog(f.rootUUID, rootKey)
	f.authority.addEntry(0, f.grantContent(f.rootUUID))
	f.authority.commitAndSeal()
	return f
}

// grantChild has R create an auth log whose root is grantData: the grant is
// stored, sequenced in R's log, and published so the child's first
// checkpoint can prove it against R's on-chain accumulator.
func (f *ks256Forest) grantChild(id logid.UUID, grantData []byte) {
	f.t.Helper()
	idts := f.nextIdtimestamp()
	storedGrantFor(f.t, f.objects, f.rootUUID, id, "auth-log",
		gfCreate|gfExtend|gfAuthLog, idTimestamp(idts), grantData)
	f.authority.addEntry(idts, f.grantContent(id))
	f.authority.commitAndSeal()
	f.publish(f.rootUUID, f.authority, "root extend with the grant for "+id.String())
}

// openLog starts a log sealed by the forest's delegate, each seal carrying
// the KS256 on-chain delegation proof that signer issues for the log.
func (f *ks256Forest) openLog(id logid.UUID, signer *ecdsa.PrivateKey) *fixtureLog {
	f.t.Helper()
	l := newFixtureLog(f.t, f.objects, id[:], f.delegate)
	l.onchainProof = signDelegationKS256(
		f.t, signer, id.ToContractBytes32(), 0, uint64(1)<<40, &f.delegate.key.PublicKey)
	return l
}

func (f *ks256Forest) nextIdtimestamp() uint64 {
	f.idts++
	return f.idts
}

// grantContent is the content hash of id's stored create grant: the value
// ranger indexes for the grant's entry in R's log.
func (f *ks256Forest) grantContent(id logid.UUID) [32]byte {
	f.t.Helper()
	sg, err := ReadStoredGrant(f.t.Context(), f.grants, f.rootUUID, id)
	require.NoError(f.t, err)
	content, err := sg.ContentHash()
	require.NoError(f.t, err)
	return content
}

// publish assembles l's head checkpoint against the current on-chain state
// of l and of R's log, and publishes it.
func (f *ks256Forest) publish(id logid.UUID, l *fixtureLog, what string) SealedState {
	f.t.Helper()
	calldata, sealed, err := AssemblePublish(f.t.Context(), f.grants, f.leaves, f.rootUUID, id,
		l.reader(), 0, f.authority.reader(), f.logState(id), f.logState(f.rootUUID))
	require.NoError(f.t, err, what)
	f.chain.publishCheckpoint(calldata, what)
	return sealed
}

// publishFirst publishes l's first checkpoint: the contract must hold no
// state for the log before, and exactly the sealed state after.
func (f *ks256Forest) publishFirst(id logid.UUID, l *fixtureLog, what string) {
	f.t.Helper()
	require.Zero(f.t, f.logState(id).Size, "%s: the log must have no on-chain state yet", what)
	f.requireAnchored(id, f.publish(id, l, what))
}

// requireAnchored asserts the contract holds exactly the sealed state for id.
func (f *ks256Forest) requireAnchored(id logid.UUID, sealed SealedState) {
	f.t.Helper()
	state := f.logState(id)
	require.Equal(f.t, sealed.MMRSize, state.Size)
	require.Equal(f.t, sealed.Accumulator, state.Accumulator)
}

func (f *ks256Forest) logState(id logid.UUID) LogState {
	f.t.Helper()
	state, err := ReadLogState(f.t.Context(), f.client, f.chain.contract, id.ToContractBytes32())
	require.NoError(f.t, err)
	return state
}

// rootKeyOf reads the rootKey the contract recorded for a log
// (logConfig(logId).rootKey).
func (f *ks256Forest) rootKeyOf(id logid.UUID) []byte {
	f.t.Helper()
	data, err := f.chain.abi.Pack("logConfig", id.ToContractBytes32())
	require.NoError(f.t, err)
	out, err := f.client.CallContract(f.t.Context(),
		ethereum.CallMsg{To: &f.chain.contract, Data: data}, nil)
	require.NoError(f.t, err)
	values, err := f.chain.abi.Unpack("logConfig", out)
	require.NoError(f.t, err)
	return abi.ConvertType(values[0], new(logConfigOut)).(*logConfigOut).RootKey
}

// logConfigOut mirrors the contract's LogConfig tuple.
type logConfigOut struct {
	Kind          uint8
	AuthLogId     [32]byte
	RootKey       []byte
	InitializedAt *big.Int
}

// deployERC1271Wallet deploys a smart account that answers ERC-1271 for a
// 65-byte signature its owner makes over the hash it is asked about.
// testdata/SOURCE.erc1271_signer_mock records where the bytecode comes from.
func (h *chainHarness) deployERC1271Wallet(owner common.Address) common.Address {
	h.t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "erc1271-signer-mock.json"))
	require.NoError(h.t, err)
	var artefact struct {
		CreationBytecode string          `json:"creationBytecode"`
		ABI              json.RawMessage `json:"abi"`
	}
	require.NoError(h.t, json.Unmarshal(raw, &artefact))
	walletABI, err := abi.JSON(strings.NewReader(string(artefact.ABI)))
	require.NoError(h.t, err)
	bytecode, err := hex.DecodeString(strings.TrimPrefix(artefact.CreationBytecode, "0x"))
	require.NoError(h.t, err)
	args, err := walletABI.Pack("", owner)
	require.NoError(h.t, err)

	nonce := h.nonce()
	tx := types.NewContractCreation(nonce, big.NewInt(0), 1_000_000, h.gasPrice(), append(bytecode, args...))
	h.sendAndRequireSuccess(tx, "deploy ERC-1271 wallet")
	return crypto.CreateAddress(h.from, nonce)
}
