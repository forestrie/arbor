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

	"github.com/forestrie/arbor/services/pkgs/publishproof"
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
	// OutcomeSuperseded — the tx reverted, but a fresh logState read shows the
	// on-chain size already covers our sealed size (anchored by us or another
	// publisher, or subsumed by a later seal). Terminal success — ack.
	OutcomeSuperseded
	// OutcomeReverted — the tx reverted and on-chain size is still below our
	// sealed size, so this seal is unpublishable as submitted. Terminal: ack +
	// alert, do NOT retry. Retrying identical calldata against identical state
	// cannot succeed, and drop-safety comes from log self-healing, not from
	// withholding the ack — the next seal on this log re-anchors the skipped
	// range via the catch-up consistency proof (adr-0008). A dormant log that
	// never re-seals is recovered by a future re-drive ("poke") endpoint.
	OutcomeReverted
	// OutcomeUnsubmitted — the tx never entered the mempool (admission failure or
	// a stopped suffix after a sequential-admission gap) or was not mined before
	// the receipt timeout. Always retry (redelivery re-anchors idempotently).
	OutcomeUnsubmitted
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
}

func (r SubmitResult) String() string {
	switch r.Outcome {
	case OutcomePublished:
		return fmt.Sprintf("published chain=%d tx=%s gas=%d", r.ChainID, r.TxHash.Hex(), r.GasUsed)
	case OutcomeSuperseded:
		return fmt.Sprintf("superseded chain=%d reason=%s", r.ChainID, r.Reason)
	case OutcomeReverted:
		return fmt.Sprintf("reverted chain=%d reason=%s", r.ChainID, r.Reason)
	case OutcomeUnsubmitted:
		return fmt.Sprintf("unsubmitted chain=%d reason=%s", r.ChainID, r.Reason)
	default:
		return "unknown"
	}
}

// ShouldAck reports whether the queue message may be acked. Three outcomes are
// terminal and ack: Published (we anchored it), Superseded (a fresh logState
// read shows it is already anchored/subsumed), and Reverted (mined revert with
// on-chain size still below sealed — unpublishable as submitted; acked + alerted
// because it self-heals via the next seal's catch-up, adr-0008). Only
// Unsubmitted (never mined: admission failure, receipt timeout, RPC error) is
// retried via redelivery, since that same message can still succeed on retry.
func (r SubmitResult) ShouldAck() bool {
	return r.Outcome == OutcomePublished ||
		r.Outcome == OutcomeSuperseded ||
		r.Outcome == OutcomeReverted
}

// parsePublisherKey decodes the gas-only EOA private key from hex (0x optional).
func parsePublisherKey(hexKey string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(hexKey), "0x"))
}

// txSender is the RPC surface the writer needs from a chain backend. *ethclient.Client
// satisfies it; tests inject a fake to exercise nonce/send/receipt logic offline.
type txSender interface {
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	SendTransaction(ctx context.Context, tx *types.Transaction) error
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

// ChainWriter submits publishCheckpoint transactions to any configured chain,
// keyed by chainId, from a single gas-only EOA (same address on every EVM
// chain, funded per chain). It lazily dials one ethclient per chainId.
//
// The daemon uses SubmitBatch (batchsubmit.go): one PendingNonceAt per chain,
// sequential admission of a contiguous nonce block (gap-free by construction),
// and a persistent per-chain receipt collector. The CLI uses the synchronous
// Submit. Both build EIP-1559 (DynamicFeeTx) transactions and classify reverts
// against the IUnivocity error table (observability, not trust).
type ChainWriter struct {
	rpcURLs map[uint64]string
	key     *ecdsa.PrivateKey
	from    common.Address
	errABI  abi.ABI

	// Submission tuning (config-driven, P13).
	gasLimit            uint64
	maxFeeWei           *big.Int // nil -> derive from base fee
	maxPriorityWei      *big.Int // nil -> SuggestGasTipCap
	receiptTimeout      time.Duration
	receiptPollInterval time.Duration

	mu      sync.Mutex
	clients map[uint64]*ethclient.Client
	// sendLocks serialise the send phase per chain so admissions stay ordered
	// (gap-free) and nonce allocation is atomic. Held only across sends, never
	// across the receipt wait.
	sendLocks map[uint64]*sync.Mutex
	// nonces holds the per-chain in-process nonce counter. Correct because the
	// publisher EOA is single-writer (see chainNonce).
	nonces map[uint64]*chainNonce
	// trackers holds one persistent receipt collector per chain (lazy start).
	trackers map[uint64]*receiptTracker

	// readLogState reads a log's on-chain state; defaults to
	// publishproof.ReadLogState, overridable in tests.
	readLogState func(ctx context.Context, caller publishproof.ContractCaller, contract common.Address, logID [32]byte) (publishproof.LogState, error)

	// testSenders, when set for a chain, replaces the dialed client (tests only).
	testSenders map[uint64]txSender
}

// WriteConfig carries the configurable submission knobs (P13).
type WriteConfig struct {
	GasLimit                uint64
	MaxFeePerGasWei         *big.Int
	MaxPriorityFeePerGasWei *big.Int
	ReceiptTimeout          time.Duration
	ReceiptPollInterval     time.Duration
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
		maxFeeWei:           wc.MaxFeePerGasWei,
		maxPriorityWei:      wc.MaxPriorityFeePerGasWei,
		receiptTimeout:      wc.ReceiptTimeout,
		receiptPollInterval: wc.ReceiptPollInterval,
		readLogState:        publishproof.ReadLogState,
		clients:             make(map[uint64]*ethclient.Client),
		sendLocks:           make(map[uint64]*sync.Mutex),
		nonces:              make(map[uint64]*chainNonce),
		trackers:            make(map[uint64]*receiptTracker),
	}, nil
}

// sender returns the tx backend for a chain: the injected test sender when set,
// otherwise the lazily-dialed ethclient.
func (w *ChainWriter) sender(chainID uint64) (txSender, error) {
	if w.testSenders != nil {
		if s, ok := w.testSenders[chainID]; ok {
			return s, nil
		}
	}
	return w.Client(chainID)
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

func (w *ChainWriter) sendLock(chainID uint64) *sync.Mutex {
	w.mu.Lock()
	defer w.mu.Unlock()
	l, ok := w.sendLocks[chainID]
	if !ok {
		l = &sync.Mutex{}
		w.sendLocks[chainID] = l
	}
	return l
}

// feeParams returns the EIP-1559 (tip, feeCap) for a chain: the configured caps
// when both are set (no RPC), otherwise a suggested tip and a fee cap derived as
// 2*baseFee + tip, clamped to MaxFeePerGasWei when configured.
func (w *ChainWriter) feeParams(ctx context.Context, s txSender) (tip, feeCap *big.Int, err error) {
	if w.maxFeeWei != nil && w.maxPriorityWei != nil {
		return new(big.Int).Set(w.maxPriorityWei), new(big.Int).Set(w.maxFeeWei), nil
	}
	tip = w.maxPriorityWei
	if tip == nil {
		tip, err = s.SuggestGasTipCap(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("suggest tip: %w", err)
		}
	}
	head, err := s.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("latest header: %w", err)
	}
	base := head.BaseFee
	if base == nil {
		base = big.NewInt(0)
	}
	feeCap = new(big.Int).Add(new(big.Int).Mul(base, big.NewInt(2)), tip)
	if w.maxFeeWei != nil && feeCap.Cmp(w.maxFeeWei) > 0 {
		feeCap = new(big.Int).Set(w.maxFeeWei)
	}
	return tip, feeCap, nil
}

// buildAndSign builds an EIP-1559 publishCheckpoint tx and signs it.
func (w *ChainWriter) buildAndSign(
	chainID *big.Int, nonce uint64, to common.Address, data []byte, tip, feeCap *big.Int,
) (*types.Transaction, error) {
	toAddr := to
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		To:        &toAddr,
		Value:     big.NewInt(0),
		Gas:       w.gasLimit,
		GasTipCap: tip,
		GasFeeCap: feeCap,
		Data:      data,
	})
	return types.SignTx(tx, types.LatestSignerForChainID(chainID), w.key)
}

// classifyReceipt turns a mined receipt into a SubmitResult, decoding the revert
// reason (and transient/terminal split) when the tx failed.
// classifyReceipt turns a mined receipt into a SubmitResult. On a revert the ack
// decision is authoritative on on-chain size: re-read logState and mark
// Superseded (ack) iff it already covers our sealed size, else Reverted (nack).
// contract/logID/sealedSize identify the log for the re-read.
func (w *ChainWriter) classifyReceipt(
	ctx context.Context, s txSender, chainID uint64, contract common.Address,
	logID [32]byte, sealedSize uint64, tx *types.Transaction, rcpt *types.Receipt,
) SubmitResult {
	if rcpt.Status == types.ReceiptStatusSuccessful {
		return SubmitResult{Outcome: OutcomePublished, ChainID: chainID, TxHash: tx.Hash(), GasUsed: rcpt.GasUsed}
	}
	reason := w.revertReasonAt(ctx, s, tx, rcpt.BlockNumber)
	return w.revertOutcome(ctx, s, chainID, contract, logID, sealedSize, tx.Hash(), rcpt.GasUsed, reason)
}

// revertOutcome decides a revert's terminal disposition by re-reading logState:
// on-chain size ≥ sealed → Superseded (ack); a read error or size still below →
// retry (nack). The decoded revert name is kept only for observability.
func (w *ChainWriter) revertOutcome(
	ctx context.Context, s txSender, chainID uint64, contract common.Address,
	logID [32]byte, sealedSize uint64, txHash common.Hash, gasUsed uint64, reason string,
) SubmitResult {
	onchain, err := w.readLogState(ctx, s, contract, logID)
	if err != nil {
		return SubmitResult{Outcome: OutcomeUnsubmitted, ChainID: chainID, TxHash: txHash,
			GasUsed: gasUsed, Reason: "revert; logState re-read failed: " + reason}
	}
	if onchain.Size >= sealedSize {
		return SubmitResult{Outcome: OutcomeSuperseded, ChainID: chainID, TxHash: txHash,
			GasUsed: gasUsed, Reason: reason}
	}
	return SubmitResult{Outcome: OutcomeReverted, ChainID: chainID, TxHash: txHash,
		GasUsed: gasUsed, Reason: reason}
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

// Submit synchronously sends publishCheckpoint calldata to (chainID, contract)
// and waits for the classified outcome. It is the OUT-OF-PROCESS CLI one-shot
// path ONLY: it reads PendingNonceAt directly and bypasses chainNonce, so any
// in-daemon writer using it would break the counter's single-writer invariant
// (plan-2607-08 F1). Every in-daemon writer — the queue consumer and the
// resync sweep — must submit through SubmitBatch. Gas for publishCheckpoint
// is predictable, so it uses a configured gas limit rather than EstimateGas
// (P13); a would-revert therefore mines as a revert and is classified from
// the receipt.
func (w *ChainWriter) Submit(
	ctx context.Context, chainID uint64, contract common.Address, logID [32]byte, sealedSize uint64, calldata []byte,
) (SubmitResult, error) {
	s, err := w.sender(chainID)
	if err != nil {
		return SubmitResult{}, err
	}

	// Serialise the send so the nonce we read is the one we send.
	lock := w.sendLock(chainID)
	lock.Lock()
	nonce, err := s.PendingNonceAt(ctx, w.from)
	if err != nil {
		lock.Unlock()
		return SubmitResult{}, fmt.Errorf("nonce chain %d: %w", chainID, err)
	}
	tip, feeCap, err := w.feeParams(ctx, s)
	if err != nil {
		lock.Unlock()
		return SubmitResult{}, fmt.Errorf("fee params chain %d: %w", chainID, err)
	}
	signed, err := w.buildAndSign(new(big.Int).SetUint64(chainID), nonce, contract, calldata, tip, feeCap)
	if err != nil {
		lock.Unlock()
		return SubmitResult{}, fmt.Errorf("sign tx chain %d: %w", chainID, err)
	}
	sendErr := s.SendTransaction(ctx, signed)
	lock.Unlock() // release before the (slow) receipt wait
	if sendErr != nil {
		// An admission failure never mined; retry via redelivery (a would-revert
		// or already-anchored tx is caught at re-assemble). Keep a decoded name
		// for observability when the node returned revert data.
		reason := sendErr.Error()
		if name, ok := w.classifyRevert(sendErr); ok {
			reason = name
		}
		return SubmitResult{Outcome: OutcomeUnsubmitted, ChainID: chainID, Reason: reason}, nil
	}

	receipt, err := w.waitReceipt(ctx, s, signed.Hash())
	if err != nil {
		return SubmitResult{}, fmt.Errorf("await receipt chain %d: %w", chainID, err)
	}
	return w.classifyReceipt(ctx, s, chainID, contract, logID, sealedSize, signed, receipt), nil
}

// RevertLabel maps a revert reason to a bounded Prometheus label: the decoded
// IUnivocity error name when recognised, else "unrecognized" (raw revert strings
// are unbounded — they stay in logs, not metrics). R2-5.
func RevertLabel(reason string) string {
	if _, ok := knownRevertNames[reason]; ok {
		return reason
	}
	return "unrecognized"
}

func (w *ChainWriter) waitReceipt(
	ctx context.Context, s txSender, hash common.Hash,
) (*types.Receipt, error) {
	deadline := time.Now().Add(w.receiptTimeout)
	for {
		receipt, err := s.TransactionReceipt(ctx, hash)
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

// tipLagBlockNotFound reports whether an eth_call error is the public-RPC tip
// lag where the receipt's block is not yet queryable. Different backends phrase
// it differently: some return "block not found: 0x…", Base Sepolia's public RPC
// returns a JSON-RPC error `{"code":3,"message":"Unknown block"}`. Both mean the
// same thing — retriable, not a contract revert. Matching the raw JSON-RPC
// code:3 is unsafe (that code is also "execution reverted"), so we match the
// message text of the known block-unavailable phrasings.
func tipLagBlockNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "block not found") ||
		strings.Contains(msg, "unknown block")
}

// revertReasonAt re-runs the mined tx as an eth_call at its block to recover the
// revert reason (mirrors chainHarness.revertReason). Retries briefly when the
// RPC tip lags the receipt block so the decoded IUnivocity name is not masked
// by "block not found".
func (w *ChainWriter) revertReasonAt(
	ctx context.Context, s txSender, tx *types.Transaction, block *big.Int,
) string {
	msg := ethereum.CallMsg{From: w.from, To: tx.To(), Gas: tx.Gas(), Data: tx.Data()}
	deadline := time.Now().Add(w.receiptTimeout)
	var err error
	for {
		_, err = s.CallContract(ctx, msg, block)
		if err == nil {
			return "reverted without reason"
		}
		if reason, ok := w.classifyRevert(err); ok {
			return reason
		}
		if !tipLagBlockNotFound(err) || time.Now().After(deadline) {
			return err.Error()
		}
		select {
		case <-ctx.Done():
			return err.Error()
		case <-time.After(w.receiptPollInterval):
		}
	}
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
	// The bare error name is the classification/metric key; args would inflate
	// label cardinality (R2-5) and are recoverable from the raw receipt.
	return abiErr.Name, true
}

// knownRevertNames is the set of decodable IUnivocity error names, used to bound
// the revert metric label (RevertLabel).
// calldataInvalidReverts are revert reasons that are properties of the
// SUBMITTED BYTES, not of chain or account state. Identical calldata will fail
// identically forever, so re-driving one is pure waste: malformed CBOR/COSE, a
// signature that does not verify, a length or algorithm the contract rejects,
// an id that does not match. The only thing that can fix these is a NEW seal,
// which arrives as a changed ETag and clears the poison entry on its own.
//
// Everything NOT in this set is treated as possibly-resolvable and aged within
// the sweep horizon, because external action can make the same bytes valid
// later. InvalidPaymentReceipt is the instructive case and is deliberately
// ABSENT here: funding or registering the instance makes the identical
// checkpoint publishable, so it is retryable-in-principle and the horizon —
// not this table — is what bounds it. Likewise MissingDelegationCert and
// CheckpointIndexOutOfDelegationRange, which a later certificate satisfies,
// and LogNotFound/NotInitialized, which owner ordering resolves.
//
// Unknown reasons (a contract error added after this table) fall through to
// the retry branch by design: the horizon still bounds them, and silently
// dropping an unrecognised revert would be the worse failure.
var calldataInvalidReverts = map[string]struct{}{
	// Structure / encoding of the submitted checkpoint.
	"InvalidCheckpointCose":        {},
	"InvalidCoseCborStructure":     {},
	"UnexpectedMajorType":          {},
	"ClaimNotFound":                {},
	"ProofPayloadExceedsMaxHeight": {},
	"InvalidAccumulatorLength":     {},
	// Signatures and keys that do not verify against what was sent.
	"SignatureVerificationFailed":        {},
	"ConsistencyReceiptSignatureInvalid": {},
	"DelegationSignatureInvalid":         {},
	"InvalidSignatureLength":             {},
	"InvalidDelegationSignatureLength":   {},
	"InvalidDelegationKeyLength":         {},
	"InvalidRootKeyLength":               {},
	"InvalidRecoveryId":                  {},
	"RecoveryIdDuplicate":                {},
	"DuplicateRootKeyInDelegation":       {},
	"RecoveredKeyMismatchIncludedKey":    {},
	"InvalidSignatureChain":              {},
	// Identity mismatches between the payload and its target.
	"ReceiptLogIdMismatch":        {},
	"DelegationLogIdMismatch":     {},
	"GrantDataMustMatchBootstrap": {},
	// Algorithm / shape the contract will never accept for this log.
	"UnsupportedAlgorithm":         {},
	"DelegationUnsupportedForAlg":  {},
	"InconsistentReceiptSignature": {},
	"InvalidReceiptInclusionProof": {},
	"FirstCheckpointSizeTooSmall":  {},
	// ADR-0008: algData elements or policy flag bits the presented algorithm
	// does not consume are properties of the submitted bytes; only a new seal
	// changes them. The WebAuthn ceremony-verification reverts
	// (InvalidWebAuthnAssertion etc.) are deliberately ABSENT: this publisher
	// never submits WebAuthn proofs (basic compat), so hitting one means an
	// encoder/contract mismatch better surfaced by horizon-bounded retry noise
	// than silently settled. Classification is backoff/metrics, not security.
	"UnexpectedDelegationAlgData":      {},
	"UnsupportedDelegationPolicyFlags": {},
}

// RevertIsCalldataInvalid reports whether a decoded revert reason can never be
// resolved by re-submitting the same calldata. Callers use it to settle a seal
// immediately (with an alert) instead of retrying it to the sweep horizon.
func RevertIsCalldataInvalid(reason string) bool {
	if reason == "" {
		return false
	}
	_, ok := calldataInvalidReverts[reason]
	return ok
}

var knownRevertNames = func() map[string]struct{} {
	parsed, err := abi.JSON(strings.NewReader(univocityErrorsABI))
	if err != nil {
		return map[string]struct{}{}
	}
	m := make(map[string]struct{}, len(parsed.Errors))
	for name := range parsed.Errors {
		m[name] = struct{}{}
	}
	return m
}()

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
  {"type":"error","name":"InconsistentReceiptSignature","inputs":[{"name":"algProvided","type":"int64"},{"name":"algLog","type":"int64"}]},
  {"type":"error","name":"DelegationUnsupportedForAlg","inputs":[{"name":"alg","type":"int64"}]},
  {"type":"error","name":"DuplicateRootKeyInDelegation","inputs":[]},
  {"type":"error","name":"RecoveredKeyMismatchIncludedKey","inputs":[]},
  {"type":"error","name":"MissingRootKeyForRecovery","inputs":[]},
  {"type":"error","name":"MissingCheckpointSignerKey","inputs":[]},
  {"type":"error","name":"InvalidDelegationSignatureLength","inputs":[{"name":"length","type":"uint256"}]},
  {"type":"error","name":"InvalidDelegationKeyLength","inputs":[{"name":"length","type":"uint256"}]},
  {"type":"error","name":"InvalidRecoveryId","inputs":[{"name":"value","type":"uint8"}]},
  {"type":"error","name":"RecoveryIdDuplicate","inputs":[]},
  {"type":"error","name":"LogRootKeyNotSet","inputs":[]},
  {"type":"error","name":"InvalidAccumulatorLength","inputs":[{"name":"expected","type":"uint256"},{"name":"actual","type":"uint256"}]},
  {"type":"error","name":"InvalidRootKeyLength","inputs":[{"name":"length","type":"uint256"}]},
  {"type":"error","name":"ProofPayloadExceedsMaxHeight","inputs":[]},
  {"type":"error","name":"UnsupportedAlgorithm","inputs":[{"name":"alg","type":"int64"}]},
  {"type":"error","name":"InvalidSignatureLength","inputs":[{"name":"expected","type":"uint256"},{"name":"actual","type":"uint256"}]},
  {"type":"error","name":"InvalidCoseCborStructure","inputs":[]},
  {"type":"error","name":"SignatureVerificationFailed","inputs":[]},
  {"type":"error","name":"ClaimNotFound","inputs":[{"name":"key","type":"int64"}]},
  {"type":"error","name":"UnexpectedMajorType","inputs":[{"name":"actual","type":"uint8"},{"name":"expected","type":"uint8"}]},
  {"type":"error","name":"InvalidReceiptInclusionProof","inputs":[]},
  {"type":"error","name":"InvalidPaymentReceipt","inputs":[]},
  {"type":"error","name":"ReceiptLogIdMismatch","inputs":[{"name":"expected","type":"bytes32"},{"name":"actual","type":"bytes32"}]},
  {"type":"error","name":"LogNotFound","inputs":[{"name":"logId","type":"bytes32"}]},
  {"type":"error","name":"NotInitialized","inputs":[]},
  {"type":"error","name":"AlreadyInitialized","inputs":[]},
  {"type":"error","name":"FirstCheckpointSizeTooSmall","inputs":[]},
  {"type":"error","name":"GrantDataMustMatchBootstrap","inputs":[]},
  {"type":"error","name":"InvalidSignatureChain","inputs":[]},
  {"type":"error","name":"UnexpectedDelegationAlgData","inputs":[{"name":"count","type":"uint256"}]},
  {"type":"error","name":"UnsupportedDelegationPolicyFlags","inputs":[{"name":"unsupported","type":"uint256"}]},
  {"type":"error","name":"InvalidWebAuthnAssertion","inputs":[]},
  {"type":"error","name":"DelegationChallengeMismatch","inputs":[]},
  {"type":"error","name":"DelegationUserPresenceRequired","inputs":[]},
  {"type":"error","name":"DelegationUserVerificationRequired","inputs":[]},
  {"type":"error","name":"DelegationRpIdMismatch","inputs":[]}
]`
