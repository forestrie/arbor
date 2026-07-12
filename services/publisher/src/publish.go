package publisher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/go-merklelog/massifs"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/arbor/services/pkgs/publishproof"
)

// MassifReaderFactory builds an R2-backed massif/checkpoint reader for a log.
// *Readers is the production implementation; the interface lets tests inject
// in-memory readers, mirroring the grants publishproof.ObjectGetter seam.
type MassifReaderFactory interface {
	Massif(logID logid.UUID, massifHeight uint8) (massifs.ObjectReader, error)
}

// PublishStatus is the terminal classification of a one-shot publish attempt.
type PublishStatus int

const (
	// StatusPublished — the checkpoint was anchored on-chain by this attempt.
	StatusPublished PublishStatus = iota
	// StatusAlreadyAnchored — the on-chain state already covers this seal
	// (idempotent success; natural under permissionless concurrency).
	StatusAlreadyAnchored
	// StatusOwnerNotAnchored — the grant's owner log is not yet anchored over
	// the grant leaf; retry after the owner (root/authority) is published.
	StatusOwnerNotAnchored
	// StatusChainNotConfigured — the forest is bound to a chain absent from
	// UNIVOCITY_RPC_URLS (D3); skip + alert, leave queued for later.
	StatusChainNotConfigured
	// StatusReverted — the tx mined as a revert and on-chain size is still below
	// our sealed size, so this seal is unpublishable as submitted. Terminal: ack
	// + alert with the reason. Not a lost checkpoint — the next seal on this log
	// re-anchors the skipped range via catch-up (adr-0008).
	StatusReverted
	// StatusRetry — the tx never mined (admission failure, receipt timeout, or an
	// RPC/infra error), so the same message can still succeed. Retry (do not ack)
	// — redelivery re-anchors idempotently.
	StatusRetry
)

func (s PublishStatus) String() string {
	switch s {
	case StatusPublished:
		return "published"
	case StatusAlreadyAnchored:
		return "already_anchored"
	case StatusOwnerNotAnchored:
		return "owner_not_anchored"
	case StatusChainNotConfigured:
		return "chain_not_configured"
	case StatusReverted:
		return "reverted"
	case StatusRetry:
		return "retry"
	default:
		return "unknown"
	}
}

// PublishResult is the outcome of publishing one checkpoint object.
type PublishResult struct {
	Status   PublishStatus
	Key      string
	R        logid.UUID
	LogID    logid.UUID
	ChainID  uint64
	Contract common.Address
	TxHash   common.Hash
	// SealedSize is the target seal's mmr size; OnchainSize is the resolved
	// contract's logState size before this attempt (anchor-lag inputs).
	SealedSize  uint64
	OnchainSize uint64
	Reason      string // decoded revert name, or skip explanation
}

// ShouldAck reports whether the queue message may be acked. Three terminal
// statuses ack: Published (we anchored it), AlreadyAnchored (a fresh logState
// read shows it is anchored/subsumed), and Reverted (mined revert, unpublishable
// as submitted — acked + alerted; it self-heals via the next seal's catch-up,
// adr-0008). Retry and OwnerNotAnchored leave the message for redelivery.
func (r PublishResult) ShouldAck() bool {
	return r.Status == StatusPublished ||
		r.Status == StatusAlreadyAnchored ||
		r.Status == StatusReverted
}

// Publisher is the one-shot publish core: it turns a checkpoint object key into
// an on-chain anchoring, resolving the forest's (chainId, contract) from public
// R2 genesis (ADR-0047) and submitting with the gas-only EOA. It is safe for
// concurrent use.
type Publisher struct {
	grants  publishproof.ObjectGetter
	readers MassifReaderFactory
	writer  *ChainWriter
	logger  *slog.Logger
}

// NewPublisher wires the core from config. doer is the shared pooled HTTP
// client; httpClient is its underlying *http.Client for the public grant store.
func NewPublisher(cfg Config, httpClient *HTTPClient, logger *slog.Logger) (*Publisher, error) {
	writer, err := NewChainWriter(cfg.RPCURLs, cfg.PublisherKeyHex, WriteConfig{
		GasLimit:                cfg.GasLimit,
		MaxFeePerGasWei:         cfg.MaxFeePerGasWei,
		MaxPriorityFeePerGasWei: cfg.MaxPriorityFeePerGasWei,
		ReceiptTimeout:          cfg.ReceiptTimeout,
		ReceiptPollInterval:     cfg.ReceiptPollInterval,
	})
	if err != nil {
		return nil, err
	}
	return &Publisher{
		grants:  publishproof.NewPublicBucketGetter(cfg.GrantStoreURL, httpClient.GetClient()),
		readers: NewReaders(cfg, httpClient, logger),
		writer:  writer,
		logger:  logger,
	}, nil
}

// Close releases dialed chain clients.
func (p *Publisher) Close() { p.writer.Close() }

// From is the publisher's gas-only EOA address.
func (p *Publisher) From() common.Address { return p.writer.From() }

// SubmitBatch submits a group of assembled checkpoints (daemon path). Receipts
// are confirmed asynchronously; each request's Ack fires when terminal.
func (p *Publisher) SubmitBatch(ctx context.Context, reqs []AssembledPublish) {
	p.writer.SubmitBatch(ctx, reqs)
}

// Assemble runs the read phase for a checkpoint key: resolve the forest, read
// on-chain state, and build the publishCheckpoint calldata — all from public R2
// + RPC, no nonce. When ready is true, calldata is set and res carries the
// forest/contract/size context (Status unset; the caller submits and finalises
// with FinalizeResult). When ready is false, res carries a terminal early-exit
// Status (already-anchored → ack; owner-not-anchored / chain-not-configured →
// retry). A non-nil error is an unexpected infrastructure failure worth retrying.
func (p *Publisher) Assemble(ctx context.Context, key string) (calldata []byte, res PublishResult, ready bool, err error) {
	ck, err := ParseCheckpointKey(key)
	if err != nil {
		return nil, PublishResult{}, false, err
	}
	res = PublishResult{Key: key, LogID: ck.LogID}

	// 1. Resolve the forest's (R, chainId, contract) from public R2 genesis.
	fc, err := publishproof.ResolveForestContract(ctx, p.grants, ck.LogID)
	if err != nil {
		if errors.Is(err, publishproof.ErrForestNotResolved) {
			res.Status = StatusOwnerNotAnchored // no forest binding yet visible; retry
			res.Reason = "forest not resolved: " + err.Error()
			return nil, res, false, nil
		}
		return nil, res, false, fmt.Errorf("resolve forest for %s: %w", ck.LogID, err)
	}
	res.R, res.ChainID, res.Contract = fc.R, fc.ChainID, fc.Contract

	// 2. Select the chain client (D3: unconfigured chain -> skip + alert).
	client, err := p.writer.Client(fc.ChainID)
	if err != nil {
		if errors.Is(err, ErrChainNotConfigured) {
			res.Status = StatusChainNotConfigured
			res.Reason = fmt.Sprintf("chainId %d not in UNIVOCITY_RPC_URLS", fc.ChainID)
			return nil, res, false, nil
		}
		return nil, res, false, fmt.Errorf("chain client %d: %w", fc.ChainID, err)
	}

	// 3. Determine the grant's owner log so we can read its on-chain state and
	//    build its reader (grant inclusion lives in the owner/authority log).
	sg, err := publishproof.ReadStoredGrant(ctx, p.grants, fc.R, ck.LogID)
	if err != nil {
		return nil, res, false, fmt.Errorf("read stored grant %s: %w", ck.LogID, err)
	}

	// 4. Build target + owner readers (forest-uniform massif height).
	targetReader, err := p.readers.Massif(ck.LogID, ck.MassifHeight)
	if err != nil {
		return nil, res, false, fmt.Errorf("target reader %s: %w", ck.LogID, err)
	}
	ownerReader := targetReader
	if sg.OwnerLogID != ck.LogID {
		ownerReader, err = p.readers.Massif(sg.OwnerLogID, ck.MassifHeight)
		if err != nil {
			return nil, res, false, fmt.Errorf("owner reader %s: %w", sg.OwnerLogID, err)
		}
	}

	// 5. Read on-chain state for both logs on the resolved contract.
	targetState, err := publishproof.ReadLogState(ctx, client, fc.Contract, ck.LogID.ToContractBytes32())
	if err != nil {
		return nil, res, false, fmt.Errorf("read logState(target) %s: %w", ck.LogID, err)
	}
	res.OnchainSize = targetState.Size
	ownerState := targetState
	if sg.OwnerLogID != ck.LogID {
		ownerState, err = publishproof.ReadLogState(ctx, client, fc.Contract, sg.OwnerLogID.ToContractBytes32())
		if err != nil {
			return nil, res, false, fmt.Errorf("read logState(owner) %s: %w", sg.OwnerLogID, err)
		}
	}

	// 6. Assemble the publishCheckpoint calldata from public data.
	calldata, sealed, err := publishproof.AssemblePublish(
		ctx, p.grants, fc.R, ck.LogID,
		targetReader, ck.MassifIndex, ownerReader,
		targetState, ownerState,
	)
	if err != nil {
		switch {
		case errors.Is(err, publishproof.ErrAlreadyAnchored):
			res.Status = StatusAlreadyAnchored
			res.SealedSize = targetState.Size
			return nil, res, false, nil
		case errors.Is(err, publishproof.ErrOwnerNotAnchored):
			res.Status = StatusOwnerNotAnchored
			res.Reason = err.Error()
			return nil, res, false, nil
		default:
			return nil, res, false, fmt.Errorf("assemble publish %s: %w", ck.LogID, err)
		}
	}
	res.SealedSize = sealed.MMRSize
	return calldata, res, true, nil
}

// FinalizeResult maps a submission outcome onto the assembled PublishResult.
// Shared by the CLI (synchronous) and the daemon collector callback.
func FinalizeResult(res PublishResult, sub SubmitResult) PublishResult {
	res.TxHash = sub.TxHash
	res.Reason = sub.Reason
	switch sub.Outcome {
	case OutcomePublished:
		res.Status = StatusPublished
	case OutcomeSuperseded:
		// Reverted, but a fresh logState read shows it is already anchored/subsumed.
		res.Status = StatusAlreadyAnchored
	case OutcomeReverted:
		// Mined revert, on-chain still below sealed: unpublishable as submitted.
		// Terminal ack + alert; self-heals via the next seal's catch-up (adr-0008).
		res.Status = StatusReverted
	default: // OutcomeUnsubmitted — never mined; retry via redelivery.
		res.Status = StatusRetry
	}
	return res
}

// Publish anchors a single checkpoint and waits for the outcome (CLI one-shot).
// The daemon uses Assemble + SubmitBatch instead. It never returns an error for
// the expected "not yet / not here" outcomes — those are carried in
// PublishResult.Status; a non-nil error is unexpected infrastructure failure.
func (p *Publisher) Publish(ctx context.Context, key string) (PublishResult, error) {
	calldata, res, ready, err := p.Assemble(ctx, key)
	if err != nil || !ready {
		return res, err
	}
	sub, err := p.writer.Submit(ctx, res.ChainID, res.Contract, res.LogID.ToContractBytes32(), res.SealedSize, calldata)
	if err != nil {
		return res, fmt.Errorf("submit %s chain %d: %w", res.LogID, res.ChainID, err)
	}
	return FinalizeResult(res, sub), nil
}
