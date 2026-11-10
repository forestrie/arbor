package univocity

// An anvil harness for tests that need univocity's real contract: it deploys
// the release-pinned ImutableUnivocity and publishes first checkpoints
// through publishproof.AssemblePublish. It is a minimal copy of the pieces of
// services/pkgs/publishproof's slice-01 test harness (integration_test.go,
// ks256_first_checkpoint_test.go, assemble_test.go, grantstore_test.go),
// which cannot be imported from another module. The contract artefact is the
// same file: that package's testdata/deploy-manifest-<release>.json.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/arbor/services/pkgs/publishproof"
	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/go-merklelog/massifs"
	mlcose "github.com/forestrie/go-merklelog/massifs/cose"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/fxamacker/cbor/v2"
)

// anvilRelease is the univocity release Lane A deploys.
const anvilRelease = "v0.3.0"

const (
	anvilKey0Hex   = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	anvilMassifH   = uint8(8)
	anvilAlgKS256  = int64(-65799)
	anvilGfCreate  = uint64(1) << 32
	anvilGfExtend  = uint64(1) << 33
	anvilGfAuthLog = uint64(1)
)

// --- in-memory R2-shaped objects --------------------------------------------

type avObjects struct{ objects map[string][]byte }

func newAvObjects() *avObjects { return &avObjects{objects: map[string][]byte{}} }

func (m *avObjects) ListObjects(_ context.Context, prefix, _ string, _ int) (merklelog.ListPage, error) {
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

func (m *avObjects) GetObject(_ context.Context, key string, opts merklelog.GetOptions) (merklelog.GetResult, error) {
	data, ok := m.objects[key]
	if !ok {
		return merklelog.GetResult{}, fmt.Errorf("%s: %w", key, massifstorage.ErrDoesNotExist)
	}
	start := min(opts.RangeStart, int64(len(data)))
	end := int64(len(data))
	if opts.RangeLength > 0 && start+opts.RangeLength < end {
		end = start + opts.RangeLength
	}
	out := make([]byte, end-start)
	copy(out, data[start:end])
	return merklelog.GetResult{Data: out, ETag: fmt.Sprintf("%d", len(data))}, nil
}

func (m *avObjects) PutObject(_ context.Context, key string, data []byte, opts merklelog.PutOptions) (merklelog.PutResult, error) {
	if opts.FailIfExists {
		if _, ok := m.objects[key]; ok {
			return merklelog.PutResult{}, fmt.Errorf("%s: %w", key, massifstorage.ErrExistsOC)
		}
	}
	m.objects[key] = append([]byte{}, data...)
	return merklelog.PutResult{ETag: fmt.Sprintf("%d", len(data))}, nil
}

func (m *avObjects) DeleteObject(_ context.Context, key string) error {
	delete(m.objects, key)
	return nil
}

// avGetter is the publisher's ObjectGetter over the public grant layout.
type avGetter map[string][]byte

func (m avGetter) Get(_ context.Context, key string) ([]byte, error) {
	b, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%s: %w", key, massifstorage.ErrDoesNotExist)
	}
	return b, nil
}

// putPublishedGrant stores a create grant for subject, owned by r, in the
// publisher's layout: a COSE Sign1 whose payload is sha256 of the embedded
// grant, with the sequenced idtimestamp in the unprotected header.
func (m *avObjects) putPublishedGrant(t *testing.T, r, subject logid.UUID, flags uint64, idts uint64, grantData []byte) {
	t.Helper()
	logWire, ownerWire := subject.ToPaddedWire32(), r.ToPaddedWire32()
	flagBytes := binary.BigEndian.AppendUint64(nil, flags)
	embedded, err := cbor.Marshal(map[int64]any{
		1: logWire[:], 2: ownerWire[:], 3: flagBytes, 4: uint64(1000), 5: uint64(0), 6: grantData,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(embedded)
	unprotected := map[int64]any{-65538: embedded}
	if idts != 0 {
		unprotected[-65537] = binary.BigEndian.AppendUint64(nil, idts)
	}
	body, err := cbor.Marshal(cbor.Tag{Number: 18, Content: []any{
		[]byte{0xa1, 0x01, 0x26}, unprotected, digest[:], make([]byte, 64)}})
	if err != nil {
		t.Fatal(err)
	}
	m.objects["forests/forest/"+r.String()+"/grants/auth-log/"+subject.String()+".cbor"] = body
}

// --- fixture log: real massif and checkpoint objects ------------------------

type avSealer struct {
	signer *mlcose.TestCoseSigner
	key    ecdsa.PrivateKey
}

func newAvSealer(t *testing.T) *avSealer {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &avSealer{signer: mlcose.NewTestCoseSigner(t, *p256), key: *p256}
}

type avLog struct {
	t          *testing.T
	client     *avObjects
	logID      massifstorage.LogID
	store      *merklelog.Store
	mc         massifs.MassifContext
	sealer     *avSealer
	sealedSize uint64
	proof      *delegationcert.OnchainDelegationProof
}

func newAvLog(t *testing.T, client *avObjects, id logid.UUID, sealer *avSealer) *avLog {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	factory, err := merklelog.NewFactory(client, anvilMassifH, logger)
	must(t, err)
	store, err := factory.NewStore(massifstorage.LogID(id[:]))
	must(t, err)
	must(t, store.SelectLog(t.Context(), massifstorage.LogID(id[:])))
	mc, err := massifs.CreateFirstMassifContext(t.Context(), 0, anvilMassifH)
	must(t, err)
	return &avLog{t: t, client: client, logID: id[:], store: store, mc: mc, sealer: sealer}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// addEntry appends and indexes one entry as the ranger committer does.
func (l *avLog) addEntry(idts uint64, content [32]byte) {
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], idts)
	leaf := sha256.Sum256(append(be[:], content[:]...))
	_, err := l.mc.AddIndexedEntry(leaf[:])
	must(l.t, err)
	must(l.t, l.mc.IndexLeaf(idts, content[:]))
}

func (l *avLog) commitAndSeal() {
	ctx := l.t.Context()
	must(l.t, massifs.CommitContext(ctx, l.store, &l.mc))
	size := l.mc.RangeCount()
	peaks, err := mmr.PeakHashes(&l.mc, size-1)
	must(l.t, err)
	proof, err := massifs.BuildConsistencyProof(&l.mc, l.sealedSize, size)
	must(l.t, err)
	opts := []massifs.CheckpointSignOption{massifs.WithPeakReceipts([]byte("univocity-anvil-test-key"))}
	if l.proof != nil {
		raw, err := cbor.Marshal(l.proof)
		must(l.t, err)
		opts = append(opts, massifs.WithUnprotectedExtras(
			map[int64]cbor.RawMessage{massifs.SealDelegationProofLabel: raw}))
	}
	data, err := massifs.SignCheckpointReceipt(l.sealer.signer, proof, peaks, opts...)
	must(l.t, err)
	must(l.t, l.store.Put(ctx, l.mc.Start.MassifIndex, massifstorage.ObjectCheckpoint, data, false))
	l.sealedSize = size
}

func (l *avLog) reader() *merklelog.Store {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	factory, err := merklelog.NewFactory(l.client, anvilMassifH, logger)
	must(l.t, err)
	store, err := factory.NewStore(l.logID)
	must(l.t, err)
	must(l.t, store.SelectLog(l.t.Context(), l.logID))
	return store
}

// signAvDelegation has the log's root key authorise the delegate for the log
// (the contract's delegation Sig_structure, delegationVerifier.sol).
func signAvDelegation(t *testing.T, root *ecdsa.PrivateKey, logID [32]byte, mmrEnd uint64, delegated *ecdsa.PublicKey) *delegationcert.OnchainDelegationProof {
	t.Helper()
	protected := []byte{0xa1, 0x01, 0x3a, 0x00, 0x01, 0x01, 0x06}
	x, y := make([]byte, 32), make([]byte, 32)
	delegated.X.FillBytes(x)
	delegated.Y.FillBytes(y)
	payload := []byte("forestrie.univocity.delegation.v1")
	payload = append(payload, logID[:]...)
	payload = binary.BigEndian.AppendUint64(payload, 0)
	payload = binary.BigEndian.AppendUint64(payload, mmrEnd)
	payload = append(payload, x...)
	payload = append(payload, y...)
	sig, err := crypto.Sign(crypto.Keccak256(publishproof.SigStructure(protected, payload)), root)
	must(t, err)
	sig[64] += 27
	return &delegationcert.OnchainDelegationProof{
		ProtectedHeader: protected, DelegationKey: append(x, y...),
		MMRStart: 0, MMREnd: mmrEnd, Signature: sig,
	}
}

// --- anvil and the contract -------------------------------------------------

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

// startAnvil starts a private anvil and returns its client and RPC URL, or
// skips when anvil is not installed.
func startAnvil(t *testing.T) (*ethclient.Client, string) {
	t.Helper()
	bin, ok := anvilBinary()
	if !ok {
		t.Skip("anvil not installed; skipping on-chain test")
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	port := lis.Addr().(*net.TCPAddr).Port
	must(t, lis.Close())
	cmd := exec.Command(bin, "--port", fmt.Sprintf("%d", port), "--silent")
	must(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for {
		client, err := ethclient.Dial(url)
		if err == nil {
			if _, err = client.ChainID(t.Context()); err == nil {
				return client, url
			}
			client.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("anvil did not become ready on %s: %v", url, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type avChain struct {
	t        *testing.T
	client   *ethclient.Client
	key      *ecdsa.PrivateKey
	from     common.Address
	chainID  *big.Int
	contract common.Address
	abi      abi.ABI
}

// deployAvUnivocity deploys ImutableUnivocity from the release manifest
// shared with publishproof's tests, bootstrapped to a KS256 address.
func deployAvUnivocity(t *testing.T, client *ethclient.Client, bootstrapKey []byte) *avChain {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "pkgs", "publishproof", "testdata",
		"deploy-manifest-"+anvilRelease+".json"))
	must(t, err)
	var manifest struct {
		Contracts map[string]struct {
			CreationBytecode string          `json:"creationBytecode"`
			ABI              json.RawMessage `json:"abi"`
		} `json:"contracts"`
	}
	must(t, json.Unmarshal(raw, &manifest))
	entry, ok := manifest.Contracts["ImutableUnivocity"]
	if !ok {
		t.Fatal("manifest must carry ImutableUnivocity")
	}
	parsed, err := abi.JSON(strings.NewReader(string(entry.ABI)))
	must(t, err)
	bytecode, err := hex.DecodeString(strings.TrimPrefix(entry.CreationBytecode, "0x"))
	must(t, err)
	key, err := crypto.HexToECDSA(anvilKey0Hex)
	must(t, err)
	chainID, err := client.ChainID(t.Context())
	must(t, err)
	args, err := parsed.Pack("", anvilAlgKS256, bootstrapKey)
	must(t, err)

	h := &avChain{t: t, client: client, key: key, from: crypto.PubkeyToAddress(key.PublicKey),
		chainID: chainID, abi: parsed}
	nonce := h.nonce()
	h.send(types.NewContractCreation(nonce, big.NewInt(0), 8_000_000, h.gasPrice(), append(bytecode, args...)),
		"deploy ImutableUnivocity")
	h.contract = crypto.CreateAddress(h.from, nonce)
	return h
}

func (h *avChain) nonce() uint64 {
	n, err := h.client.PendingNonceAt(h.t.Context(), h.from)
	must(h.t, err)
	return n
}

func (h *avChain) gasPrice() *big.Int {
	p, err := h.client.SuggestGasPrice(h.t.Context())
	must(h.t, err)
	return p
}

func (h *avChain) send(tx *types.Transaction, what string) *types.Receipt {
	ctx := h.t.Context()
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(h.chainID), h.key)
	must(h.t, err)
	must(h.t, h.client.SendTransaction(ctx, signed))
	deadline := time.Now().Add(15 * time.Second)
	for {
		receipt, err := h.client.TransactionReceipt(ctx, signed.Hash())
		if err == nil {
			if receipt.Status != types.ReceiptStatusSuccessful {
				_, cerr := h.client.CallContract(ctx, ethereum.CallMsg{
					From: h.from, To: signed.To(), Data: signed.Data(), Gas: signed.Gas()}, receipt.BlockNumber)
				h.t.Fatalf("%s reverted: %v", what, cerr)
			}
			return receipt
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%s: transaction not mined: %v", what, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (h *avChain) publishCheckpoint(calldata []byte, what string) {
	h.t.Helper()
	h.send(types.NewTransaction(h.nonce(), h.contract, big.NewInt(0), 4_000_000, h.gasPrice(), calldata), what)
}

// --- a KS256 forest on anvil ------------------------------------------------

// avForest is a forest on anvil whose root R is a KS256 address; every log is
// owned by R and sealed by one standing P-256 delegate.
type avForest struct {
	t         *testing.T
	client    *ethclient.Client
	rpcURL    string
	chain     *avChain
	objects   *avObjects
	delegate  *avSealer
	rootKey   *ecdsa.PrivateKey
	R         logid.UUID
	authority *avLog
	idts      uint64
}

// newAvForest deploys the contract, stores R's self-grant and opens R's
// authority log with the self-grant as its first entry.
func newAvForest(t *testing.T, R logid.UUID) *avForest {
	t.Helper()
	client, url := startAnvil(t)
	rootKey, err := crypto.GenerateKey()
	must(t, err)
	rootAddr := crypto.PubkeyToAddress(rootKey.PublicKey).Bytes()
	f := &avForest{t: t, client: client, rpcURL: url, objects: newAvObjects(),
		delegate: newAvSealer(t), rootKey: rootKey, R: R,
		chain: deployAvUnivocity(t, client, rootAddr)}
	f.objects.putPublishedGrant(t, R, R, anvilGfCreate|anvilGfExtend|anvilGfAuthLog, 0, rootAddr)
	f.authority = f.openLog(R, rootKey)
	f.authority.addEntry(0, f.grantContent(R))
	f.authority.commitAndSeal()
	return f
}

func (f *avForest) openLog(id logid.UUID, signer *ecdsa.PrivateKey) *avLog {
	l := newAvLog(f.t, f.objects, id, f.delegate)
	l.proof = signAvDelegation(f.t, signer, id.ToContractBytes32(), uint64(1)<<40, &f.delegate.key.PublicKey)
	return l
}

func (f *avForest) grantContent(id logid.UUID) [32]byte {
	sg, err := publishproof.ReadStoredGrant(f.t.Context(), avGetter(f.objects.objects), f.R, id)
	must(f.t, err)
	content, err := sg.ContentHash()
	must(f.t, err)
	return content
}

// publish assembles l's head checkpoint against the current chain state and
// publishes it.
func (f *avForest) publish(id logid.UUID, l *avLog, what string) {
	f.t.Helper()
	calldata, _, err := publishproof.AssemblePublish(f.t.Context(), avGetter(f.objects.objects),
		publishproof.NewGrantLeafIndex(), f.R, id,
		l.reader(), 0, f.authority.reader(), f.logState(id), f.logState(f.R))
	must(f.t, err)
	f.chain.publishCheckpoint(calldata, what)
}

func (f *avForest) logState(id logid.UUID) publishproof.LogState {
	st, err := publishproof.ReadLogState(f.t.Context(), f.client, f.chain.contract, id.ToContractBytes32())
	must(f.t, err)
	return st
}

// publishRoot publishes R's bootstrap checkpoint.
func (f *avForest) publishRoot() { f.publish(f.R, f.authority, "root bootstrap") }

// registerChild has R grant the creation of child C with the given KS256
// root key, publishes R's checkpoint covering that grant, then publishes C's
// first checkpoint. The chain then records C under owner R with childAddr.
func (f *avForest) registerChild(id logid.UUID, childKey *ecdsa.PrivateKey) {
	f.t.Helper()
	f.grantChild(id, crypto.PubkeyToAddress(childKey.PublicKey).Bytes())
	child := f.openLog(id, childKey)
	var content [32]byte
	content[31] = 0xc0
	f.idts++
	child.addEntry(f.idts, content)
	child.commitAndSeal()
	f.publish(id, child, "first checkpoint of "+id.String())
}

func (f *avForest) grantChild(id logid.UUID, grantData []byte) {
	f.t.Helper()
	f.idts++
	f.objects.putPublishedGrant(f.t, f.R, id, anvilGfCreate|anvilGfExtend|anvilGfAuthLog, f.idts, grantData)
	f.authority.addEntry(f.idts, f.grantContent(id))
	f.authority.commitAndSeal()
	f.publish(f.R, f.authority, "root extend covering the grant for "+id.String())
}
