package publisher

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// AssembledPublish is a ready-to-send checkpoint: calldata already built by the
// assemble (read) phase, plus the callback the receipt collector fires exactly
// once with the terminal submission outcome. Ack must be safe to call from a
// goroutine.
type AssembledPublish struct {
	ChainID  uint64
	Contract common.Address
	Calldata []byte
	Ack      func(SubmitResult)
}

// SubmitBatch groups requests by chain and submits each group with sequential
// nonce admission. It returns once all sends are issued; receipts are confirmed
// asynchronously by the persistent per-chain collector, which fires each
// request's Ack. ctx must be the daemon's long-lived context — it binds the
// collector lifetime (on cancel, outstanding items stay unacked and redeliver).
func (w *ChainWriter) SubmitBatch(ctx context.Context, reqs []AssembledPublish) {
	if len(reqs) == 0 {
		return
	}
	byChain := make(map[uint64][]AssembledPublish)
	for _, r := range reqs {
		byChain[r.ChainID] = append(byChain[r.ChainID], r)
	}
	var wg sync.WaitGroup
	for chainID, group := range byChain {
		wg.Add(1)
		go func(chainID uint64, group []AssembledPublish) {
			defer wg.Done()
			w.submitChainGroup(ctx, chainID, group)
		}(chainID, group)
	}
	wg.Wait()
}

// submitChainGroup sends a contiguous nonce block for one chain under the send
// lock, stopping on the first admission failure. Nothing above a failed nonce is
// ever sent, so the nonce sequence is gap-free by construction. Admitted txs are
// handed to the collector; unsent requests are nacked for redelivery.
func (w *ChainWriter) submitChainGroup(ctx context.Context, chainID uint64, group []AssembledPublish) {
	s, err := w.sender(chainID)
	if err != nil {
		nackFrom(group, 0, chainID, fmt.Errorf("sender chain %d: %w", chainID, err))
		return
	}
	tracker := w.tracker(ctx, chainID, s)
	chainIDBig := new(big.Int).SetUint64(chainID)

	lock := w.sendLock(chainID)
	lock.Lock()
	defer lock.Unlock()

	nonce, err := s.PendingNonceAt(ctx, w.from)
	if err != nil {
		nackFrom(group, 0, chainID, fmt.Errorf("nonce chain %d: %w", chainID, err))
		return
	}
	tip, feeCap, err := w.feeParams(ctx, s)
	if err != nil {
		nackFrom(group, 0, chainID, fmt.Errorf("fee params chain %d: %w", chainID, err))
		return
	}

	for i, r := range group {
		signed, err := w.buildAndSign(chainIDBig, nonce+uint64(i), r.Contract, r.Calldata, tip, feeCap)
		if err != nil {
			// Nothing at i or above was sent — nack the whole remainder.
			nackFrom(group, i, chainID, fmt.Errorf("sign chain %d: %w", chainID, err))
			return
		}
		if err := s.SendTransaction(ctx, signed); err != nil {
			// Admission failure. Classify this one (a node may reject with revert
			// data at send), then STOP: the suffix is never sent, keeping the
			// nonce sequence gap-free.
			if reason, ok := w.classifyRevert(err); ok {
				r.Ack(SubmitResult{Outcome: OutcomeReverted, ChainID: chainID,
					Reason: reason, Retryable: revertRetryable(reason)})
			} else {
				r.Ack(SubmitResult{Outcome: OutcomeUnsubmitted, ChainID: chainID, Reason: err.Error()})
			}
			nackFrom(group, i+1, chainID, nil)
			return
		}
		tracker.watch(signed, r.Ack)
	}
}

// nackFrom acks group[from:] as unsubmitted (retry via redelivery).
func nackFrom(group []AssembledPublish, from int, chainID uint64, reason error) {
	msg := ""
	if reason != nil {
		msg = reason.Error()
	}
	for _, r := range group[from:] {
		r.Ack(SubmitResult{Outcome: OutcomeUnsubmitted, ChainID: chainID, Reason: msg})
	}
}

// watchItem tracks one admitted tx awaiting its receipt.
type watchItem struct {
	tx    *types.Transaction
	ack   func(SubmitResult)
	start time.Time
}

// receiptTracker is the persistent per-chain receipt collector. One goroutine
// polls all outstanding hashes on a single ticker and fires each request's Ack
// the instant its receipt resolves (or the receipt timeout elapses).
type receiptTracker struct {
	w       *ChainWriter
	chainID uint64
	s       txSender

	mu    sync.Mutex
	items map[common.Hash]*watchItem
}

// tracker returns the persistent collector for a chain, starting it on first use.
func (w *ChainWriter) tracker(ctx context.Context, chainID uint64, s txSender) *receiptTracker {
	w.mu.Lock()
	defer w.mu.Unlock()
	if t, ok := w.trackers[chainID]; ok {
		return t
	}
	t := &receiptTracker{w: w, chainID: chainID, s: s, items: make(map[common.Hash]*watchItem)}
	w.trackers[chainID] = t
	go t.run(ctx)
	return t
}

func (t *receiptTracker) watch(tx *types.Transaction, ack func(SubmitResult)) {
	t.mu.Lock()
	t.items[tx.Hash()] = &watchItem{tx: tx, ack: ack, start: time.Now()}
	t.mu.Unlock()
}

func (t *receiptTracker) snapshot() []*watchItem {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*watchItem, 0, len(t.items))
	for _, it := range t.items {
		out = append(out, it)
	}
	return out
}

// resolve removes the item and fires its Ack once, in a goroutine so a slow ack
// (HTTP) never stalls the poll loop.
func (t *receiptTracker) resolve(hash common.Hash, res SubmitResult) {
	t.mu.Lock()
	it, ok := t.items[hash]
	if ok {
		delete(t.items, hash)
	}
	t.mu.Unlock()
	if ok {
		go it.ack(res)
	}
}

func (t *receiptTracker) run(ctx context.Context) {
	tick := time.NewTicker(t.w.receiptPollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		for _, it := range t.snapshot() {
			hash := it.tx.Hash()
			rcpt, err := t.s.TransactionReceipt(ctx, hash)
			switch {
			case err == nil:
				t.resolve(hash, t.w.classifyReceipt(ctx, t.s, t.chainID, it.tx, rcpt))
			case errors.Is(err, ethereum.NotFound):
				if time.Since(it.start) > t.w.receiptTimeout {
					t.resolve(hash, SubmitResult{Outcome: OutcomeUnsubmitted,
						ChainID: t.chainID, TxHash: hash, Reason: "receipt timeout"})
				}
				// else: still pending, keep polling.
			default:
				// transient RPC error; keep the item and retry next tick.
			}
		}
	}
}
