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
)

// fakeSender is a programmable txSender for offline batch-submit tests.
type fakeSender struct {
	mu         sync.Mutex
	nonce      uint64
	nonceCalls int
	sent       []*types.Transaction
	sendErr    map[uint64]error // nonce -> admission failure
	timeout    map[uint64]bool  // nonce -> admitted but never mined
	receipts   map[common.Hash]*types.Receipt
	callErr    error // returned by CallContract (revert-reason replay)
}

func newFakeSender(nonce uint64) *fakeSender {
	return &fakeSender{
		nonce:    nonce,
		sendErr:  map[uint64]error{},
		timeout:  map[uint64]bool{},
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
	if !f.timeout[tx.Nonce()] {
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

func TestClassifyReceiptTransientVsTerminal(t *testing.T) {
	w := newTestWriter(t)
	ctx := context.Background()
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 0, Gas: 21000})

	// Success.
	if r := w.classifyReceipt(ctx, newFakeSender(0), 1, tx, &types.Receipt{Status: types.ReceiptStatusSuccessful}); r.Outcome != OutcomePublished {
		t.Errorf("success outcome = %v, want Published", r.Outcome)
	}

	// Reverted, transient (SizeMustIncrease) -> Retryable.
	transient := newFakeSender(0)
	transient.callErr = &fakeDataError{data: revertData(t, "SizeMustIncrease", uint64(3), uint64(5))}
	r := w.classifyReceipt(ctx, transient, 1, tx, &types.Receipt{Status: types.ReceiptStatusFailed, BlockNumber: big.NewInt(1)})
	if r.Outcome != OutcomeReverted || !r.Retryable {
		t.Errorf("transient revert = {%v retryable=%v}, want {Reverted retryable=true}", r.Outcome, r.Retryable)
	}

	// Reverted, terminal (GrantRequirement) -> not retryable.
	terminal := newFakeSender(0)
	terminal.callErr = &fakeDataError{data: revertData(t, "GrantRequirement", big.NewInt(1), big.NewInt(2))}
	r = w.classifyReceipt(ctx, terminal, 1, tx, &types.Receipt{Status: types.ReceiptStatusFailed, BlockNumber: big.NewInt(1)})
	if r.Outcome != OutcomeReverted || r.Retryable {
		t.Errorf("terminal revert = {%v retryable=%v}, want {Reverted retryable=false}", r.Outcome, r.Retryable)
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

// revertData builds "0x"+selector+abi-encoded-args for a named IUnivocity error.
func revertData(t *testing.T, name string, args ...interface{}) string {
	t.Helper()
	errABI, err := abi.JSON(strings.NewReader(univocityErrorsABI))
	if err != nil {
		t.Fatalf("parse errors abi: %v", err)
	}
	e := errABI.Errors[name]
	packed, err := e.Inputs.Pack(args...)
	if err != nil {
		t.Fatalf("pack %s args: %v", name, err)
	}
	return "0x" + hex.EncodeToString(append(append([]byte{}, e.ID.Bytes()[:4]...), packed...))
}
