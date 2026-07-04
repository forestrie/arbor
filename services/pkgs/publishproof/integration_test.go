package publishproof

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/go-merklelog/massifs"
	mlcose "github.com/forestrie/go-merklelog/massifs/cose"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
)

// --- in-memory R2-shaped object client -------------------------------------

type memObjectClient struct {
	objects map[string][]byte
}

func newMemObjectClient() *memObjectClient {
	return &memObjectClient{objects: map[string][]byte{}}
}

func (m *memObjectClient) ListObjects(_ context.Context, prefix, _ string, _ int) (merklelog.ListPage, error) {
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	page := merklelog.ListPage{}
	for _, k := range keys {
		page.Objects = append(page.Objects, merklelog.ListObject{Key: k, Size: int64(len(m.objects[k]))})
	}
	return page, nil
}

func (m *memObjectClient) GetObject(_ context.Context, key string, opts merklelog.GetOptions) (merklelog.GetResult, error) {
	data, ok := m.objects[key]
	if !ok {
		return merklelog.GetResult{}, fmt.Errorf("%s: %w", key, massifstorage.ErrDoesNotExist)
	}
	start := opts.RangeStart
	if start > int64(len(data)) {
		start = int64(len(data))
	}
	end := int64(len(data))
	if opts.RangeLength > 0 && start+opts.RangeLength < end {
		end = start + opts.RangeLength
	}
	out := make([]byte, end-start)
	copy(out, data[start:end])
	return merklelog.GetResult{Data: out, ETag: fmt.Sprintf("%d", len(data))}, nil
}

func (m *memObjectClient) PutObject(_ context.Context, key string, data []byte, opts merklelog.PutOptions) (merklelog.PutResult, error) {
	if opts.FailIfExists {
		if _, ok := m.objects[key]; ok {
			return merklelog.PutResult{}, fmt.Errorf("%s: %w", key, massifstorage.ErrExistsOC)
		}
	}
	m.objects[key] = append([]byte{}, data...)
	return merklelog.PutResult{ETag: fmt.Sprintf("%d", len(data))}, nil
}

func (m *memObjectClient) DeleteObject(_ context.Context, key string) error {
	delete(m.objects, key)
	return nil
}

// --- fixture log: real massif + checkpoint objects in the R2 layout --------

const fixtureMassifHeight = uint8(8)

type fixtureLog struct {
	t      *testing.T
	client *memObjectClient
	logID  massifstorage.LogID
	store  *merklelog.Store
	mc     massifs.MassifContext
	signer *fixtureSealer
}

type fixtureSealer struct {
	rootSigner massifs.RootSigner
	coseSigner *mlcose.TestCoseSigner
	key        ecdsa.PrivateKey
}

func newFixtureSealer(t *testing.T) *fixtureSealer {
	codec, err := massifs.NewCBORCodec()
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key := *p256
	return &fixtureSealer{
		rootSigner: massifs.NewRootSigner("publishproof-tests", codec),
		coseSigner: mlcose.NewTestCoseSigner(t, key),
		key:        key,
	}
}

func newFixtureLog(t *testing.T, client *memObjectClient, logID []byte, sealer *fixtureSealer) *fixtureLog {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	factory, err := merklelog.NewFactory(client, fixtureMassifHeight, logger)
	require.NoError(t, err)
	store, err := factory.NewStore(massifstorage.LogID(logID))
	require.NoError(t, err)
	require.NoError(t, store.SelectLog(t.Context(), massifstorage.LogID(logID)))
	mc, err := massifs.CreateFirstMassifContext(t.Context(), 0, fixtureMassifHeight)
	require.NoError(t, err)
	return &fixtureLog{t: t, client: client, logID: logID, store: store, mc: mc, signer: sealer}
}

// addLeaves appends pre-hashed leaf values and returns the resulting mmr size.
func (f *fixtureLog) addLeaves(leaves ...[32]byte) uint64 {
	var size uint64
	var err error
	for _, leaf := range leaves {
		size, err = f.mc.AddIndexedEntry(leaf[:])
		require.NoError(f.t, err)
	}
	return size
}

// commitAndSeal writes the massif object and a sealer-format checkpoint for
// the current mmr size, mirroring the production write path.
func (f *fixtureLog) commitAndSeal() {
	ctx := f.t.Context()
	require.NoError(f.t, massifs.CommitContext(ctx, f.store, &f.mc))

	size := f.mc.RangeCount()
	peaks, err := mmr.PeakHashes(&f.mc, size-1)
	require.NoError(f.t, err)
	state := massifs.MMRState{
		Version:   int(massifs.MMRStateVersionCurrent),
		MMRSize:   size,
		Peaks:     peaks,
		Timestamp: time.Now().UnixMilli(),
	}
	pub := f.signer.key.PublicKey
	subject := fmt.Sprintf("massif/%d", f.mc.Start.MassifIndex)
	data, err := f.signer.rootSigner.Sign1(f.signer.coseSigner, "publishproof-test-key", &pub, subject, state, nil)
	require.NoError(f.t, err)
	require.NoError(f.t, f.store.Put(ctx, f.mc.Start.MassifIndex, massifstorage.ObjectCheckpoint, data, false))
}

// reader returns a fresh store over the same objects, so publisher reads are
// not served from the fixture writer's cache.
func (f *fixtureLog) reader() *merklelog.Store {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	factory, err := merklelog.NewFactory(f.client, fixtureMassifHeight, logger)
	require.NoError(f.t, err)
	store, err := factory.NewStore(f.logID)
	require.NoError(f.t, err)
	require.NoError(f.t, store.SelectLog(f.t.Context(), f.logID))
	return store
}

// --- anvil harness ----------------------------------------------------------

// Anvil's first funded dev account; also used as the KS256 log signer.
const anvilKey0Hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

func anvilBinary() (string, bool) {
	if p, err := exec.LookPath("anvil"); err == nil {
		return p, true
	}
	p := filepath.Join(os.Getenv("HOME"), ".foundry", "bin", "anvil")
	if _, err := os.Stat(p); err == nil {
		return p, true
	}
	return "", false
}

func startAnvil(t *testing.T) *ethclient.Client {
	bin, ok := anvilBinary()
	if !ok {
		t.Skip("anvil not installed; skipping on-chain tracer bullet")
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := lis.Addr().(*net.TCPAddr).Port
	require.NoError(t, lis.Close())

	cmd := exec.Command(bin, "--port", fmt.Sprintf("%d", port), "--silent")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for {
		client, err := ethclient.Dial(url)
		if err == nil {
			if _, err = client.ChainID(t.Context()); err == nil {
				return client
			}
			client.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("anvil did not become ready on %s: %v", url, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type deployManifest struct {
	Contracts map[string]struct {
		CreationBytecode string          `json:"creationBytecode"`
		ABI              json.RawMessage `json:"abi"`
	} `json:"contracts"`
}

type chainHarness struct {
	t        *testing.T
	client   *ethclient.Client
	key      *ecdsa.PrivateKey
	from     common.Address
	chainID  *big.Int
	contract common.Address
	abi      abi.ABI
}

const algKS256 = int64(-65799)

func deployUnivocity(t *testing.T, client *ethclient.Client, signer common.Address) *chainHarness {
	ctx := t.Context()
	raw, err := os.ReadFile(filepath.Join("testdata", "deploy-manifest-v0.1.5.json"))
	require.NoError(t, err)
	var manifest deployManifest
	require.NoError(t, json.Unmarshal(raw, &manifest))
	entry, ok := manifest.Contracts["ImutableUnivocity"]
	require.True(t, ok, "manifest must carry ImutableUnivocity")

	parsedABI, err := abi.JSON(strings.NewReader(string(entry.ABI)))
	require.NoError(t, err)
	bytecode, err := hex.DecodeString(strings.TrimPrefix(entry.CreationBytecode, "0x"))
	require.NoError(t, err)

	key, err := crypto.HexToECDSA(anvilKey0Hex)
	require.NoError(t, err)
	from := crypto.PubkeyToAddress(key.PublicKey)
	chainID, err := client.ChainID(ctx)
	require.NoError(t, err)

	// constructor(int64 bootstrapAlg, bytes bootstrapKey): KS256 keys are the
	// 20-byte signer address.
	args, err := parsedABI.Pack("", algKS256, signer.Bytes())
	require.NoError(t, err)

	h := &chainHarness{t: t, client: client, key: key, from: from, chainID: chainID, abi: parsedABI}
	nonce := h.nonce()
	tx := types.NewContractCreation(nonce, big.NewInt(0), 8_000_000, h.gasPrice(), append(bytecode, args...))
	h.sendAndRequireSuccess(tx, "deploy ImutableUnivocity")
	h.contract = crypto.CreateAddress(from, nonce)
	return h
}

func (h *chainHarness) nonce() uint64 {
	nonce, err := h.client.PendingNonceAt(h.t.Context(), h.from)
	require.NoError(h.t, err)
	return nonce
}

func (h *chainHarness) gasPrice() *big.Int {
	price, err := h.client.SuggestGasPrice(h.t.Context())
	require.NoError(h.t, err)
	return price
}

func (h *chainHarness) sendAndRequireSuccess(tx *types.Transaction, what string) *types.Receipt {
	ctx := h.t.Context()
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(h.chainID), h.key)
	require.NoError(h.t, err)
	require.NoError(h.t, h.client.SendTransaction(ctx, signed))

	deadline := time.Now().Add(15 * time.Second)
	for {
		receipt, err := h.client.TransactionReceipt(ctx, signed.Hash())
		if err == nil {
			if receipt.Status != types.ReceiptStatusSuccessful {
				h.t.Fatalf("%s reverted: %s", what, h.revertReason(signed, receipt.BlockNumber))
			}
			return receipt
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%s: transaction not mined: %v", what, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (h *chainHarness) revertReason(tx *types.Transaction, block *big.Int) string {
	msg := ethereum.CallMsg{From: h.from, To: tx.To(), Data: tx.Data(), Gas: tx.Gas()}
	_, err := h.client.CallContract(h.t.Context(), msg, block)
	if err == nil {
		return "no revert reason recovered"
	}
	return err.Error()
}

// publishCheckpoint submits the calldata and asserts CheckpointPublished.
func (h *chainHarness) publishCheckpoint(calldata []byte, what string) {
	tx := types.NewTransaction(h.nonce(), h.contract, big.NewInt(0), 4_000_000, h.gasPrice(), calldata)
	receipt := h.sendAndRequireSuccess(tx, what)

	topic := h.abi.Events["CheckpointPublished"].ID
	for _, lg := range receipt.Logs {
		if len(lg.Topics) > 0 && lg.Topics[0] == topic {
			return
		}
	}
	h.t.Fatalf("%s: CheckpointPublished not emitted", what)
}

// signReceiptKS256 signs the contract's Sig_structure over the consistency
// commitment for the final accumulator, as the log signer.
func signReceiptKS256(t *testing.T, key *ecdsa.PrivateKey, protected []byte, finalAccumulator [][32]byte) []byte {
	commitment := ConsistencyCommitment(finalAccumulator)
	digest := crypto.Keccak256(SigStructure(protected, commitment[:]))
	sig, err := crypto.Sign(digest, key)
	require.NoError(t, err)
	sig[64] += 27
	return sig
}

// --- the tracer bullet -------------------------------------------------------

const (
	gfCreate  = uint64(1) << 32
	gfExtend  = uint64(1) << 33
	gfAuthLog = uint64(1)
	gfDataLog = uint64(2)
)

var (
	gcAuthLog = new(big.Int).Lsh(big.NewInt(1), 224)
	gcDataLog = new(big.Int).Lsh(big.NewInt(2), 224)
)

var protectedKS256 = []byte{0xa1, 0x01, 0x3a, 0x00, 0x01, 0x01, 0x06}

func idTimestamp(n uint64) [8]byte {
	var out [8]byte
	for i := 7; i >= 0 && n > 0; i-- {
		out[i] = byte(n)
		n >>= 8
	}
	return out
}

func emptyDelegation() DelegationProof {
	return DelegationProof{ProtectedHeader: []byte{}, DelegationKey: []byte{}, Signature: []byte{}}
}

// TestTracerBulletPublishFromR2Fixtures is the FOR-315 vertical slice: R2
// object fixtures written with the production massif and checkpoint formats
// are read back by publishproof, turned into publishCheckpoint calldata, and
// published against the release-pinned contract on anvil. The on-chain
// logState must advance to each sealed size (extend and first child-log
// checkpoint; root bootstrap is exercised as deploy-time setup).
func TestTracerBulletPublishFromR2Fixtures(t *testing.T) {
	ctx := t.Context()
	client := startAnvil(t)

	signerKey, err := crypto.HexToECDSA(anvilKey0Hex)
	require.NoError(t, err)
	signerAddr := crypto.PubkeyToAddress(signerKey.PublicKey)

	harness := deployUnivocity(t, client, signerAddr)

	rootLogID := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	targetLogID := mustHex(t, "101112131415161718191a1b1c1d1e1f")
	rootLogId32 := bytes32FromLow(t, hex.EncodeToString(rootLogID))
	targetLogId32 := bytes32FromLow(t, hex.EncodeToString(targetLogID))

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

	gTarget := PublishGrant{
		LogId:      targetLogId32,
		Grant:      new(big.Int).SetUint64(gfCreate | gfExtend | gfDataLog),
		Request:    gcDataLog,
		MaxHeight:  1000,
		MinGrowth:  0,
		OwnerLogId: rootLogId32,
		GrantData:  signerAddr.Bytes(),
	}
	idt1 := idTimestamp(2)
	leafGT, err := gTarget.LeafCommitment(idt1)
	require.NoError(t, err)

	sealer := newFixtureSealer(t)
	objects := newMemObjectClient()

	// Authority log: the root grant, sealed, then extended with the target
	// grant and sealed again.
	authority := newFixtureLog(t, objects, rootLogID, sealer)
	require.Equal(t, uint64(1), authority.addLeaves(leafG0))
	authority.commitAndSeal()

	// Bootstrap the root log on-chain (deploy-time setup per plan D3).
	proof, sealed, err := BuildCheckpointProof(ctx, authority.reader(), 0, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), sealed.MMRSize)
	calldata, err := EncodePublishCheckpoint(
		ConsistencyReceipt{
			ProtectedHeader:   protectedKS256,
			Signature:         signReceiptKS256(t, signerKey, protectedKS256, sealed.Accumulator),
			ConsistencyProofs: []ConsistencyProof{proof},
			DelegationProof:   emptyDelegation(),
		},
		InclusionProof{Index: 0, Path: [][32]byte{}},
		idt0,
		g0,
	)
	require.NoError(t, err)
	harness.publishCheckpoint(calldata, "bootstrap root log")

	state, err := ReadLogState(ctx, client, harness.contract, rootLogId32)
	require.NoError(t, err)
	require.Equal(t, uint64(1), state.Size)

	// Extend the authority log with the target grant leaf.
	authoritySize := authority.addLeaves(leafGT)
	require.Equal(t, uint64(3), authoritySize)
	authority.commitAndSeal()

	proof, sealed, err = BuildCheckpointProof(ctx, authority.reader(), 1, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(3), sealed.MMRSize)
	calldata, err = EncodePublishCheckpoint(
		ConsistencyReceipt{
			ProtectedHeader:   protectedKS256,
			Signature:         signReceiptKS256(t, signerKey, protectedKS256, sealed.Accumulator),
			ConsistencyProofs: []ConsistencyProof{proof},
			DelegationProof:   emptyDelegation(),
		},
		InclusionProof{Index: 0, Path: [][32]byte{}},
		idt0,
		g0,
	)
	require.NoError(t, err)
	harness.publishCheckpoint(calldata, "extend authority with target grant")

	state, err = ReadLogState(ctx, client, harness.contract, rootLogId32)
	require.NoError(t, err)
	require.Equal(t, uint64(3), state.Size)

	// Grant inclusion proof for the target grant in the authority log.
	authorityMC, err := massifs.GetMassifContext(ctx, authority.reader(), 0)
	require.NoError(t, err)
	grantInclusion, err := BuildInclusionProof(&authorityMC, authoritySize, 1)
	require.NoError(t, err)

	// Target log: three data entries, sealed — the first child-log checkpoint.
	target := newFixtureLog(t, objects, targetLogID, sealer)
	var dataLeaves []([32]byte)
	for i := range 5 {
		leaf := bytes32FromLow(t, fmt.Sprintf("%02x", 0xd0+i))
		dataLeaves = append(dataLeaves, leaf)
	}
	firstSize := target.addLeaves(dataLeaves[:3]...)
	require.Equal(t, uint64(4), firstSize)
	target.commitAndSeal()

	proof, sealed, err = BuildCheckpointProof(ctx, target.reader(), 0, 0)
	require.NoError(t, err)
	require.Equal(t, firstSize, sealed.MMRSize)
	calldata, err = EncodePublishCheckpoint(
		ConsistencyReceipt{
			ProtectedHeader:   protectedKS256,
			Signature:         signReceiptKS256(t, signerKey, protectedKS256, sealed.Accumulator),
			ConsistencyProofs: []ConsistencyProof{proof},
			DelegationProof:   emptyDelegation(),
		},
		grantInclusion,
		idt1,
		gTarget,
	)
	require.NoError(t, err)
	harness.publishCheckpoint(calldata, "first target checkpoint")

	state, err = ReadLogState(ctx, client, harness.contract, targetLogId32)
	require.NoError(t, err)
	require.Equal(t, firstSize, state.Size)
	require.Equal(t, sealed.Accumulator, state.Accumulator)

	// Extend the target log: two more entries, sealed, published.
	extendSize := target.addLeaves(dataLeaves[3:]...)
	require.Greater(t, extendSize, firstSize)
	target.commitAndSeal()

	proof, sealed, err = BuildCheckpointProof(ctx, target.reader(), firstSize, 0)
	require.NoError(t, err)
	require.Equal(t, extendSize, sealed.MMRSize)
	calldata, err = EncodePublishCheckpoint(
		ConsistencyReceipt{
			ProtectedHeader:   protectedKS256,
			Signature:         signReceiptKS256(t, signerKey, protectedKS256, sealed.Accumulator),
			ConsistencyProofs: []ConsistencyProof{proof},
			DelegationProof:   emptyDelegation(),
		},
		grantInclusion,
		idt1,
		gTarget,
	)
	require.NoError(t, err)
	harness.publishCheckpoint(calldata, "extend target checkpoint")

	state, err = ReadLogState(ctx, client, harness.contract, targetLogId32)
	require.NoError(t, err)
	require.Equal(t, extendSize, state.Size)
	require.Equal(t, sealed.Accumulator, state.Accumulator)
}
