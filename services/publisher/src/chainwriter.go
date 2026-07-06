package publisher

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ErrChainNotConfigured is returned when a resolved forest is bound to a chain
// that is absent from UNIVOCITY_RPC_URLS (plan-2607-02 D3: skip + alert, do not
// wedge the queue).
var ErrChainNotConfigured = errors.New("chainId not configured in UNIVOCITY_RPC_URLS")

// SubmitOutcome classifies the result of a publishCheckpoint submission.
type SubmitOutcome int

const (
	// OutcomePublished — the transaction mined successfully; the checkpoint is
	// anchored.
	OutcomePublished SubmitOutcome = iota
	// OutcomeReverted — the contract rejected the submission. Reason carries the
	// decoded IUnivocity error name when recognised.
	OutcomeReverted
)

// SubmitResult is the classified outcome of a submission attempt.
type SubmitResult struct {
	Outcome SubmitOutcome
	ChainID uint64
	TxHash  common.Hash
	GasUsed uint64
	// Reason is the decoded revert name (e.g. "GrantRequirement") or the raw
	// revert string when the selector is unrecognised. Empty on success.
	Reason string
	// Retryable is set for OutcomeReverted when the revert reflects the on-chain
	// state having moved under us (a competing publisher anchored an intermediate
	// size). Redelivery rebuilds a fresh catch-up proof and succeeds, so the
	// caller must NOT ack. Deterministic reverts are terminal (Retryable=false).
	Retryable bool
}

func (r SubmitResult) String() string {
	switch r.Outcome {
	case OutcomePublished:
		return fmt.Sprintf("published chain=%d tx=%s gas=%d", r.ChainID, r.TxHash.Hex(), r.GasUsed)
	case OutcomeReverted:
		return fmt.Sprintf("reverted chain=%d reason=%s", r.ChainID, r.Reason)
	default:
		return "unknown"
	}
}

// parsePublisherKey decodes the gas-only EOA private key from hex (0x optional).
func parsePublisherKey(hexKey string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(hexKey), "0x"))
}

// ChainWriter submits publishCheckpoint transactions to any configured chain,
// keyed by chainId, from a single gas-only EOA (same address on every EVM
// chain, funded per chain). It lazily dials one ethclient per chainId and
// serialises submissions per chain so nonces stay monotonic.
//
// It promotes the anvil test harness (publishproof integration_test chainHarness)
// to a production submitter: EstimateGas gate (a revert is caught before gas is
// spent), legacy tx with SuggestGasPrice, wait for receipt, classify reverts
// against the IUnivocity error table.
type ChainWriter struct {
	rpcURLs map[uint64]string
	key     *ecdsa.PrivateKey
	from    common.Address
	errABI  abi.ABI

	// Submission tuning (config-driven, P13).
	gasLimit            uint64
	gasPriceWei         *big.Int // nil -> SuggestGasPrice
	receiptTimeout      time.Duration
	receiptPollInterval time.Duration

	mu      sync.Mutex
	clients map[uint64]*ethclient.Client
	// chainLocks serialises submissions per chain (nonce safety).
	chainLocks map[uint64]*sync.Mutex
}

// WriteConfig carries the configurable submission knobs (P13).
type WriteConfig struct {
	GasLimit            uint64
	GasPriceWei         *big.Int
	ReceiptTimeout      time.Duration
	ReceiptPollInterval time.Duration
}

// NewChainWriter builds a writer over the chainId->rpc map with the gas-only EOA.
func NewChainWriter(rpcURLs map[uint64]string, keyHex string, wc WriteConfig) (*ChainWriter, error) {
	key, err := parsePublisherKey(keyHex)
	if err != nil {
		return nil, fmt.Errorf("publisher key: %w", err)
	}
	errABI, err := abi.JSON(strings.NewReader(univocityErrorsABI))
	if err != nil {
		return nil, fmt.Errorf("parse univocity errors abi: %w", err)
	}
	if wc.ReceiptTimeout <= 0 {
		wc.ReceiptTimeout = 60 * time.Second
	}
	if wc.ReceiptPollInterval <= 0 {
		wc.ReceiptPollInterval = 200 * time.Millisecond
	}
	if wc.GasLimit == 0 {
		wc.GasLimit = 3_000_000
	}
	return &ChainWriter{
		rpcURLs:             rpcURLs,
		key:                 key,
		from:                crypto.PubkeyToAddress(key.PublicKey),
		errABI:              errABI,
		gasLimit:            wc.GasLimit,
		gasPriceWei:         wc.GasPriceWei,
		receiptTimeout:      wc.ReceiptTimeout,
		receiptPollInterval: wc.ReceiptPollInterval,
		clients:             make(map[uint64]*ethclient.Client),
		chainLocks:          make(map[uint64]*sync.Mutex),
	}, nil
}

// From is the publisher EOA address (same on every chain).
func (w *ChainWriter) From() common.Address { return w.from }

// Client returns (lazily dialing) the ethclient for a chain. It doubles as the
// publishproof ContractCaller for logState reads on that chain.
func (w *ChainWriter) Client(chainID uint64) (*ethclient.Client, error) {
	url, ok := w.rpcURLs[chainID]
	if !ok {
		return nil, ErrChainNotConfigured
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if c, ok := w.clients[chainID]; ok {
		return c, nil
	}
	c, err := ethclient.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("dial chain %d: %w", chainID, err)
	}
	w.clients[chainID] = c
	return c, nil
}

func (w *ChainWriter) chainLock(chainID uint64) *sync.Mutex {
	w.mu.Lock()
	defer w.mu.Unlock()
	l, ok := w.chainLocks[chainID]
	if !ok {
		l = &sync.Mutex{}
		w.chainLocks[chainID] = l
	}
	return l
}

// Close closes all dialed clients.
func (w *ChainWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, c := range w.clients {
		c.Close()
	}
	w.clients = make(map[uint64]*ethclient.Client)
}

// Submit sends publishCheckpoint calldata to (chainID, contract) and returns the
// classified outcome. Gas for publishCheckpoint is predictable, so it uses a
// configured gas limit rather than EstimateGas (P13); a would-revert therefore
// mines as a revert and is classified from the receipt. A reverting tx still
// consumes its nonce, which keeps the nonce sequence gap-free.
func (w *ChainWriter) Submit(
	ctx context.Context, chainID uint64, contract common.Address, calldata []byte,
) (SubmitResult, error) {
	client, err := w.Client(chainID)
	if err != nil {
		return SubmitResult{}, err
	}

	// Serialise per-chain so the nonce we read is the one we send.
	lock := w.chainLock(chainID)
	lock.Lock()
	defer lock.Unlock()

	nonce, err := client.PendingNonceAt(ctx, w.from)
	if err != nil {
		return SubmitResult{}, fmt.Errorf("nonce chain %d: %w", chainID, err)
	}
	gasPrice := w.gasPriceWei
	if gasPrice == nil {
		gasPrice, err = client.SuggestGasPrice(ctx)
		if err != nil {
			return SubmitResult{}, fmt.Errorf("gas price chain %d: %w", chainID, err)
		}
	}

	tx := types.NewTransaction(nonce, contract, big.NewInt(0), w.gasLimit, gasPrice, calldata)
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(new(big.Int).SetUint64(chainID)), w.key)
	if err != nil {
		return SubmitResult{}, fmt.Errorf("sign tx chain %d: %w", chainID, err)
	}
	if err := client.SendTransaction(ctx, signed); err != nil {
		if reason, ok := w.classifyRevert(err); ok {
			return SubmitResult{
				Outcome: OutcomeReverted, ChainID: chainID, Reason: reason,
				Retryable: revertRetryable(reason),
			}, nil
		}
		return SubmitResult{}, fmt.Errorf("send tx chain %d: %w", chainID, err)
	}

	receipt, err := w.waitReceipt(ctx, client, signed.Hash())
	if err != nil {
		return SubmitResult{}, fmt.Errorf("await receipt chain %d: %w", chainID, err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		reason := w.revertReasonAt(ctx, client, signed, receipt.BlockNumber)
		return SubmitResult{
			Outcome: OutcomeReverted, ChainID: chainID, TxHash: signed.Hash(),
			GasUsed: receipt.GasUsed, Reason: reason, Retryable: revertRetryable(reason),
		}, nil
	}
	return SubmitResult{
		Outcome: OutcomePublished, ChainID: chainID, TxHash: signed.Hash(), GasUsed: receipt.GasUsed,
	}, nil
}

// transientRevertNames are the contract errors that reflect the on-chain state
// advancing under us (a competing publisher anchored an intermediate size).
// Redelivery rebuilds a fresh catch-up proof from the new size and succeeds, so
// these must be retried, never acked-and-dropped (P1). Every other revert is
// deterministic — retrying the identical calldata cannot help — and is terminal.
var transientRevertNames = map[string]struct{}{
	"SizeMustIncrease":        {},
	"InvalidConsistencyProof": {},
	"MinGrowthNotMet":         {},
}

// revertRetryable reports whether a decoded revert reason is transient. reason
// is "Name" or "Name(args...)" (classifyRevert), so match on the leading name.
func revertRetryable(reason string) bool {
	name := reason
	if i := strings.IndexByte(reason, '('); i >= 0 {
		name = reason[:i]
	}
	_, ok := transientRevertNames[name]
	return ok
}

func (w *ChainWriter) waitReceipt(
	ctx context.Context, client *ethclient.Client, hash common.Hash,
) (*types.Receipt, error) {
	deadline := time.Now().Add(w.receiptTimeout)
	for {
		receipt, err := client.TransactionReceipt(ctx, hash)
		if err == nil {
			return receipt, nil
		}
		if !errors.Is(err, ethereum.NotFound) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for receipt %s", hash.Hex())
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(w.receiptPollInterval):
		}
	}
}

// revertReasonAt re-runs the mined tx as an eth_call at its block to recover the
// revert reason (mirrors chainHarness.revertReason).
func (w *ChainWriter) revertReasonAt(
	ctx context.Context, client *ethclient.Client, tx *types.Transaction, block *big.Int,
) string {
	msg := ethereum.CallMsg{From: w.from, To: tx.To(), Gas: tx.Gas(), GasPrice: tx.GasPrice(), Data: tx.Data()}
	_, err := client.CallContract(ctx, msg, block)
	if err == nil {
		return "reverted without reason"
	}
	if reason, ok := w.classifyRevert(err); ok {
		return reason
	}
	return err.Error()
}

// dataError is the go-ethereum interface exposing raw revert data on RPC errors.
type dataError interface{ ErrorData() interface{} }

// classifyRevert decodes an RPC/call error into an IUnivocity error name when
// the revert carries a recognised custom-error selector. Returns (reason, true)
// when classified.
func (w *ChainWriter) classifyRevert(err error) (string, bool) {
	var de dataError
	if !errors.As(err, &de) {
		return "", false
	}
	raw, ok := de.ErrorData().(string)
	if !ok || len(raw) < 10 { // "0x" + 8 hex chars (4-byte selector)
		return "", false
	}
	data := common.FromHex(raw)
	if len(data) < 4 {
		return "", false
	}
	var selector [4]byte
	copy(selector[:], data[:4])
	abiErr, matchErr := w.errABI.ErrorByID(selector)
	if matchErr != nil {
		return "", false
	}
	// Best-effort decode of args for context; the name alone is the metric key.
	if args, unpackErr := abiErr.Unpack(data); unpackErr == nil && len(args.([]interface{})) > 0 {
		return fmt.Sprintf("%s%v", abiErr.Name, args), true
	}
	return abiErr.Name, true
}

// univocityErrorsABI is the error subset a publisher can hit at publishCheckpoint,
// used only to decode revert selectors into names for classification/metrics.
// The contract remains the sole authority; this is observability, not trust.
const univocityErrorsABI = `[
  {"type":"error","name":"GrantRequirement","inputs":[{"name":"requiredGrant","type":"uint256"},{"name":"requiredRequest","type":"uint256"}]},
  {"type":"error","name":"ConsistencyReceiptSignatureInvalid","inputs":[]},
  {"type":"error","name":"InvalidConsistencyProof","inputs":[]},
  {"type":"error","name":"InvalidCheckpointCose","inputs":[]},
  {"type":"error","name":"SizeMustIncrease","inputs":[{"name":"current","type":"uint64"},{"name":"proposed","type":"uint64"}]},
  {"type":"error","name":"MaxHeightExceeded","inputs":[{"name":"size","type":"uint64"},{"name":"maxHeight","type":"uint64"}]},
  {"type":"error","name":"MinGrowthNotMet","inputs":[{"name":"current","type":"uint64"},{"name":"proposed","type":"uint64"},{"name":"minGrowth","type":"uint64"}]},
  {"type":"error","name":"CheckpointCountExceeded","inputs":[{"name":"current","type":"uint64"},{"name":"limit","type":"uint64"}]},
  {"type":"error","name":"CheckpointIndexOutOfDelegationRange","inputs":[]},
  {"type":"error","name":"DelegationSignatureInvalid","inputs":[]},
  {"type":"error","name":"DelegationLogIdMismatch","inputs":[]},
  {"type":"error","name":"MissingDelegationCert","inputs":[]},
  {"type":"error","name":"InvalidReceiptInclusionProof","inputs":[]},
  {"type":"error","name":"ReceiptLogIdMismatch","inputs":[{"name":"expected","type":"bytes32"},{"name":"actual","type":"bytes32"}]},
  {"type":"error","name":"LogNotFound","inputs":[{"name":"logId","type":"bytes32"}]},
  {"type":"error","name":"NotInitialized","inputs":[]},
  {"type":"error","name":"AlreadyInitialized","inputs":[]},
  {"type":"error","name":"FirstCheckpointSizeTooSmall","inputs":[]},
  {"type":"error","name":"GrantDataMustMatchBootstrap","inputs":[]},
  {"type":"error","name":"InvalidSignatureChain","inputs":[]}
]`
