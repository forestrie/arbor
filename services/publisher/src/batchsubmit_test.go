package publisher

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/forestrie/arbor/services/pkgs/publishproof"
)

// fakeSender is a programmable txSender for offline batch-submit tests.
type fakeSender struct {
	mu         sync.Mutex
	nonce      uint64
	nonceCalls int
	sent       []*types.Transaction
	sendErr    map[uint64]error // nonce -> admission failure
	timeout    map[uint64]bool  // nonce -> admitted but never mined
	revert     map[uint64]bool  // nonce -> mines with a failed (reverted) receipt
	receipts   map[common.Hash]*types.Receipt
	callErr    error // returned by CallContract (revert-reason replay)
	// callFailN: first N CallContract invocations return a tip-lag
	// "block not found" error before falling through to callErr.
	callFailN int
	callCalls int
}

func newFakeSender(nonce uint64) *fakeSender {
	return &fakeSender{
		nonce:    nonce,
		sendErr:  map[uint64]error{},
		timeout:  map[uint64]bool{},
		revert:   map[uint64]bool{},
		receipts: map[common.Hash]*types.Receipt{},
	}
}

func (f *fakeSender) PendingNonceAt(context.Context, common.Address) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonceCalls++
	return f.nonce, nil
}

func (f *fakeSender) SuggestGasTipCap(context.Context) (*big.Int, error) {
	return big.NewInt(1_000_000_000), nil
}

func (f *fakeSender) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return &types.Header{Number: big.NewInt(1), BaseFee: big.NewInt(1_000_000_000)}, nil
}

func (f *fakeSender) SendTransaction(_ context.Context, tx *types.Transaction) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.sendErr[tx.Nonce()]; err != nil {
		return err
	}
	f.sent = append(f.sent, tx)
	switch {
	case f.timeout[tx.Nonce()]:
		// no receipt — never mines
	case f.revert[tx.Nonce()]:
		f.receipts[tx.Hash()] = &types.Receipt{Status: types.ReceiptStatusFailed, BlockNumber: big.NewInt(1)}
	default:
		f.receipts[tx.Hash()] = &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockNumber: big.NewInt(1)}
	}
	return nil
}

func (f *fakeSender) TransactionReceipt(_ context.Context, hash common.Hash) (*types.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.receipts[hash]; ok {
		return r, nil
	}
	return nil, ethereum.NotFound
}

func (f *fakeSender) CallContract(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCalls++
	if f.callFailN > 0 {
		f.callFailN--
		return nil, errors.New("block not found: 0x29e5b11")
	}
	return nil, f.callErr
}

func (f *fakeSender) sentNonces() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]uint64, len(f.sent))
	for i, tx := range f.sent {
		out[i] = tx.Nonce()
	}
	return out
}

func writerWithSender(t *testing.T, chainID uint64, s txSender) *ChainWriter {
	t.Helper()
	w, err := NewChainWriter(map[uint64]string{chainID: "http://x"}, anvilKey0, WriteConfig{
		ReceiptPollInterval: 2 * time.Millisecond,
		ReceiptTimeout:      50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewChainWriter: %v", err)
	}
	w.testSenders = map[uint64]txSender{chainID: s}
	return w
}

// ackSink collects the per-request submit results.
type ackSink struct {
	mu  sync.Mutex
	got map[string]SubmitResult
	wg  sync.WaitGroup
}

func newAckSink() *ackSink { return &ackSink{got: map[string]SubmitResult{}} }

func (s *ackSink) req(id string, chainID uint64) AssembledPublish {
	s.wg.Add(1)
	return AssembledPublish{
		ChainID:  chainID,
		Contract: common.HexToAddress("0x01"),
		Calldata: []byte(id), // unique per request -> distinct tx hash
		Ack: func(r SubmitResult) {
			s.mu.Lock()
			s.got[id] = r
			s.mu.Unlock()
			s.wg.Done()
		},
	}
}

func (s *ackSink) waitAll(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for acks")
	}
}

func (s *ackSink) result(id string) SubmitResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got[id]
}

func TestSubmitBatchSequentialNonces(t *testing.T) {
	s := newFakeSender(5)
	w := writerWithSender(t, 1, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink := newAckSink()
	w.SubmitBatch(ctx, []AssembledPublish{sink.req("r0", 1), sink.req("r1", 1), sink.req("r2", 1)})
	sink.waitAll(t)

	if s.nonceCalls != 1 {
		t.Errorf("PendingNonceAt called %d times, want 1 (once per chain per batch)", s.nonceCalls)
	}
	if got := s.sentNonces(); len(got) != 3 || got[0] != 5 || got[1] != 6 || got[2] != 7 {
		t.Errorf("nonces = %v, want contiguous [5 6 7]", got)
	}
	for _, id := range []string{"r0", "r1", "r2"} {
		if o := sink.result(id).Outcome; o != OutcomePublished {
			t.Errorf("%s outcome = %v, want Published", id, o)
		}
	}
}

func TestSubmitBatchGapFreeOnAdmissionFailure(t *testing.T) {
	s := newFakeSender(0)
	s.sendErr[1] = errors.New("replacement transaction underpriced") // fail the 2nd nonce
	w := writerWithSender(t, 1, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink := newAckSink()
	w.SubmitBatch(ctx, []AssembledPublish{sink.req("r0", 1), sink.req("r1", 1), sink.req("r2", 1)})
	sink.waitAll(t)

	// Only nonce 0 is ever admitted — nothing above the failed nonce is sent.
	if got := s.sentNonces(); len(got) != 1 || got[0] != 0 {
		t.Errorf("sent nonces = %v, want exactly [0] (gap-free)", got)
	}
	if o := sink.result("r0").Outcome; o != OutcomePublished {
		t.Errorf("r0 outcome = %v, want Published", o)
	}
	if o := sink.result("r1").Outcome; o != OutcomeUnsubmitted {
		t.Errorf("r1 (admission failure) outcome = %v, want Unsubmitted", o)
	}
	if o := sink.result("r2").Outcome; o != OutcomeUnsubmitted {
		t.Errorf("r2 (suffix, never sent) outcome = %v, want Unsubmitted", o)
	}
}

func TestSubmitBatchReceiptTimeout(t *testing.T) {
	s := newFakeSender(0)
	s.timeout[0] = true // admitted but never mined
	w := writerWithSender(t, 1, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink := newAckSink()
	w.SubmitBatch(ctx, []AssembledPublish{sink.req("r0", 1)})
	sink.waitAll(t)

	r := sink.result("r0")
	if r.Outcome != OutcomeUnsubmitted {
		t.Errorf("outcome = %v, want Unsubmitted on receipt timeout", r.Outcome)
	}
	if !strings.Contains(r.Reason, "timeout") {
		t.Errorf("reason = %q, want it to mention timeout", r.Reason)
	}
}

// TestClassifyReceiptReReadAuthority: on a revert the ack decision is made by
// re-reading logState, not by the revert name. onchain >= sealed -> Superseded
// (ack); onchain < sealed -> Reverted (nack); read error -> Unsubmitted (nack).
func TestClassifyReceiptReReadAuthority(t *testing.T) {
	ctx := context.Background()
	addr := common.HexToAddress("0x01")
	var logID [32]byte
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 0, Gas: 21000, To: &addr})
	failed := &types.Receipt{Status: types.ReceiptStatusFailed, BlockNumber: big.NewInt(1)}

	// Success — no re-read needed.
	w := newTestWriter(t)
	if r := w.classifyReceipt(ctx, newFakeSender(0), 1, addr, logID, 10, tx, &types.Receipt{Status: types.ReceiptStatusSuccessful}); r.Outcome != OutcomePublished {
		t.Errorf("success outcome = %v, want Published", r.Outcome)
	}

	withLogState := func(size uint64, err error) *ChainWriter {
		cw := newTestWriter(t)
		cw.readLogState = func(context.Context, publishproof.ContractCaller, common.Address, [32]byte) (publishproof.LogState, error) {
			return publishproof.LogState{Size: size}, err
		}
		return cw
	}

	// Revert but on-chain already covers our sealed size -> Superseded (ack).
	if r := withLogState(10, nil).classifyReceipt(ctx, newFakeSender(0), 1, addr, logID, 10, tx, failed); r.Outcome != OutcomeSuperseded || !r.ShouldAck() {
		t.Errorf("onchain>=sealed = %v (ack=%v), want Superseded/ack", r.Outcome, r.ShouldAck())
	}
	// Revert and on-chain still below sealed -> Reverted, terminal ack+alert
	// (unpublishable as submitted; self-heals via the next seal, adr-0008).
	if r := withLogState(5, nil).classifyReceipt(ctx, newFakeSender(0), 1, addr, logID, 10, tx, failed); r.Outcome != OutcomeReverted || !r.ShouldAck() {
		t.Errorf("onchain<sealed = %v (ack=%v), want Reverted/ack", r.Outcome, r.ShouldAck())
	}
	// Re-read error -> Unsubmitted (nack, never ack on uncertainty).
	if r := withLogState(0, errors.New("rpc down")).classifyReceipt(ctx, newFakeSender(0), 1, addr, logID, 10, tx, failed); r.Outcome != OutcomeUnsubmitted || r.ShouldAck() {
		t.Errorf("reread error = %v (ack=%v), want Unsubmitted/nack", r.Outcome, r.ShouldAck())
	}
}

// TestRevertReasonAtRetriesTipLag: eth_call at the receipt block can fail with
// "block not found" when the public RPC tip lags; retry until the decoded
// IUnivocity name is available instead of surfacing the tip-lag string.
func TestRevertReasonAtRetriesTipLag(t *testing.T) {
	errABI, err := abi.JSON(strings.NewReader(univocityErrorsABI))
	if err != nil {
		t.Fatalf("parse errors abi: %v", err)
	}
	irs := errABI.Errors["InconsistentReceiptSignature"]
	args, err := irs.Inputs.Pack(int64(-7), int64(-65799))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	data := append(append([]byte{}, irs.ID.Bytes()[:4]...), args...)

	s := newFakeSender(0)
	s.callFailN = 2
	s.callErr = &fakeDataError{data: "0x" + hex.EncodeToString(data)}

	w := writerWithSender(t, 1, s)
	w.receiptPollInterval = time.Millisecond
	w.receiptTimeout = 200 * time.Millisecond

	addr := common.HexToAddress("0x01")
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 0, Gas: 21000, To: &addr})
	got := w.revertReasonAt(context.Background(), s, tx, big.NewInt(1))
	if got != "InconsistentReceiptSignature" {
		t.Fatalf("reason = %q, want InconsistentReceiptSignature (calls=%d)", got, s.callCalls)
	}
	if s.callCalls < 3 {
		t.Fatalf("callCalls = %d, want >= 3 (2 tip-lag + 1 success)", s.callCalls)
	}
}

func TestTipLagBlockNotFound(t *testing.T) {
	if !tipLagBlockNotFound(errors.New("block not found: 0x29e5b11")) {
		t.Fatal("expected tip-lag match")
	}
	// Base Sepolia's public RPC masks the receipt block behind this body; the
	// matcher must recognise it or the true revert reason is lost (FOR-377).
	if !tipLagBlockNotFound(errors.New(
		`400 Bad Request: {"jsonrpc":"2.0","id":131,"error":{"code":3,"message":"Unknown block"}}`)) {
		t.Fatal("expected tip-lag match for Base Sepolia 'Unknown block'")
	}
	if tipLagBlockNotFound(errors.New("execution reverted")) {
		t.Fatal("did not expect tip-lag match")
	}
}

// TestSubmitBatchSupersededAcks drives a reverting tx through the collector and
// asserts the re-read (onchain >= sealed) yields an ack via the batch path.
func TestSubmitBatchSupersededAcks(t *testing.T) {
	s := newFakeSender(0)
	s.revert[0] = true // the tx mines but reverts
	w := writerWithSender(t, 1, s)
	w.readLogState = func(context.Context, publishproof.ContractCaller, common.Address, [32]byte) (publishproof.LogState, error) {
		return publishproof.LogState{Size: 100}, nil // already anchored past our seal
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink := newAckSink()
	req := sink.req("r0", 1)
	req.SealedSize = 42
	w.SubmitBatch(ctx, []AssembledPublish{req})
	sink.waitAll(t)

	if r := sink.result("r0"); r.Outcome != OutcomeSuperseded || !r.ShouldAck() {
		t.Errorf("reverted-but-anchored = %v (ack=%v), want Superseded/ack", r.Outcome, r.ShouldAck())
	}
}

func TestChainNonceReseedsOnlyWhenDrained(t *testing.T) {
	s := newFakeSender(100)
	w := writerWithSender(t, 1, s)
	cn := w.nonce(1)
	ctx := context.Background()

	// First allocation seeds from the chain (drained: inflight == 0).
	base, err := cn.allocate(ctx, s, w.from, 3)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if base != 100 || s.nonceCalls != 1 {
		t.Fatalf("base=%d nonceCalls=%d, want 100/1", base, s.nonceCalls)
	}

	// Second allocation while in flight must NOT re-read the chain, and must
	// continue contiguously from the counter.
	base2, err := cn.allocate(ctx, s, w.from, 2)
	if err != nil {
		t.Fatalf("allocate 2: %v", err)
	}
	if base2 != 103 || s.nonceCalls != 1 {
		t.Errorf("base2=%d nonceCalls=%d, want 103/1 (no reseed while in flight)", base2, s.nonceCalls)
	}

	// Drain all five, then the chain nonce moves (e.g. mined elsewhere in the
	// fake, or an eviction correction). Next allocation re-seeds.
	for i := 0; i < 5; i++ {
		cn.settle()
	}
	s.nonce = 200
	base3, err := cn.allocate(ctx, s, w.from, 1)
	if err != nil {
		t.Fatalf("allocate 3: %v", err)
	}
	if base3 != 200 || s.nonceCalls != 2 {
		t.Errorf("base3=%d nonceCalls=%d, want 200/2 (reseed when drained)", base3, s.nonceCalls)
	}
}

func TestChainNonceReconcileRollsBack(t *testing.T) {
	s := newFakeSender(0)
	w := writerWithSender(t, 1, s)
	cn := w.nonce(1)

	base, err := cn.allocate(context.Background(), s, w.from, 3)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if base != 0 || cn.next != 3 || cn.inflight != 3 {
		t.Fatalf("after allocate: next=%d inflight=%d, want 3/3", cn.next, cn.inflight)
	}
	// Admitted only 1 of 3 (admission failed at nonce 1): give back the tail.
	cn.reconcile(2)
	if cn.next != 1 || cn.inflight != 1 {
		t.Errorf("after reconcile: next=%d inflight=%d, want 1/1 (rolled back to the failed nonce)", cn.next, cn.inflight)
	}
}
