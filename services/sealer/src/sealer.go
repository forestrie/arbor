package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/massifs/snowflakeid"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

const (
	// delegationCertUnprotectedLabel is the application-private COSE unprotected
	// header label for embedding the delegation certificate bytes.
	//
	// See forest-1/docs/arc-delegation-signer-cose-cbor-scitt.md.
	delegationCertUnprotectedLabel int64 = 1000
)

// CheckpointLog seals/checkpoints the provided logID using v2 massif storage schema only.
//
// This intentionally rejects legacy formats (no backwards compatibility).
//
// Concurrency note: CheckpointLog is safe to run concurrently for different logs,
// but callers should avoid running it concurrently for the same logID within a
// process. Cross-process concurrency is handled via optimistic concurrency
// (ETag / If-Match) on checkpoint writes.
func CheckpointLog(
	ctx context.Context,
	svc SealerService,
	logID massifstorage.LogID,
	massifHeight uint8,
) error {
	if svc.HTTPClient == nil {
		return fmt.Errorf("http client is required")
	}
	logger := svc.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if len(logID) == 0 {
		return fmt.Errorf("logID is required")
	}
	if massifHeight == 0 {
		return fmt.Errorf("massifHeight is required")
	}
	if svc.LeaseManager == nil {
		return fmt.Errorf("delegation lease manager is required")
	}

	// Validate the logID is a well-formed UUID.
	if _, err := uuid.FromBytes(logID); err != nil {
		return fmt.Errorf("invalid logID bytes: %w", err)
	}
	// 32-char lowercase hex for Custodian log-id resolution
	logIdHex := hex.EncodeToString(logID)

	// Build shared clients.
	s3Client, err := s3.NewClientWithCredentials(
		svc.Cfg.R2URL,
		"", // no bearer token; Sealer uses AWS credentials for authenticated writes
		svc.Cfg.AWSAccessKeyID,
		svc.Cfg.AWSSecretAccessKey,
		svc.Cfg.AWSRegion,
		svc.HTTPClient,
		logger,
	)
	if err != nil {
		return fmt.Errorf("build s3 client: %w", err)
	}

	factory, err := merklelog.NewFactory(s3Client, massifHeight, logger)
	if err != nil {
		return fmt.Errorf("build merklelog store factory: %w", err)
	}
	store, err := factory.NewStore(massifstorage.LogID(logID))
	if err != nil {
		return fmt.Errorf("build store: %w", err)
	}

	headMassifIndex, err := store.HeadIndex(ctx, massifstorage.ObjectMassifData)
	if errors.Is(err, massifstorage.ErrLogEmpty) {
		// Nothing to seal.
		return nil
	}
	if err != nil {
		return fmt.Errorf("head massif index: %w", err)
	}

	// Determine the latest existing checkpoint (if any).
	var startMassifIndex uint32 = 0
	var baseState massifs.MMRState
	lastCheckpointIndex, err := store.HeadIndex(ctx, massifstorage.ObjectCheckpoint)
	switch {
	case errors.Is(err, massifstorage.ErrLogEmpty):
		// Start from scratch.
		baseState = massifs.MMRState{MMRSize: 0}
	case err != nil:
		return fmt.Errorf("head checkpoint index: %w", err)
	default:
		data, err := store.CheckpointRead(ctx, lastCheckpointIndex)
		if err != nil {
			return fmt.Errorf("read checkpoint %d: %w", lastCheckpointIndex, err)
		}
		receipt, err := massifs.DecodeCheckpointReceipt(data)
		if err != nil {
			return fmt.Errorf("decode checkpoint %d: %w", lastCheckpointIndex, err)
		}
		startMassifIndex = lastCheckpointIndex
		// v3 checkpoint: the sealed size is the proof's tree-size-2; base peaks
		// are rehydrated from the massif on first use below.
		baseState = massifs.MMRState{MMRSize: receipt.Proof.TreeSize2}
	}

	// Process each massif from the last checkpoint to head.
	for mi := startMassifIndex; mi <= headMassifIndex; mi++ {
		mc, err := massifs.GetMassifContext(ctx, store, mi)
		if err != nil {
			return fmt.Errorf("read massif %d: %w", mi, err)
		}

		// Reject legacy massif formats.
		if mc.Start.Version != massifs.MassifCurrentVersion {
			return fmt.Errorf("legacy massif version %d detected (no backward compatibility)", mc.Start.Version)
		}
		if mc.Start.MassifHeight != massifHeight {
			return fmt.Errorf("massif height mismatch: path=%d header=%d", massifHeight, mc.Start.MassifHeight)
		}

		// Rehydrate base peaks on first use.
		if baseState.MMRSize != 0 && baseState.Peaks == nil {
			peaks, err := mmr.PeakHashes(&mc, baseState.MMRSize-1)
			if err != nil {
				return fmt.Errorf("rehydrate base peaks: %w", err)
			}
			baseState.Peaks = peaks
		}

		curSize := mc.RangeCount()
		if curSize == 0 {
			continue
		}

		var newPeaks [][]byte
		if baseState.MMRSize == 0 {
			peaks, err := mmr.PeakHashes(&mc, curSize-1)
			if err != nil {
				return fmt.Errorf("compute peaks: %w", err)
			}
			newPeaks = peaks
		} else {
			peaks, err := mc.CheckConsistency(baseState)
			if err != nil {
				return fmt.Errorf("consistency check (massif=%d): %w", mi, err)
			}
			if peaks == nil {
				// No advance since last checkpoint (or already covered).
				continue
			}
			newPeaks = peaks
		}

		// Calculate MMR range for this massif for the delegation
		// MMR size at start of massif and end of massif
		mmrStart := baseState.MMRSize
		mmrEnd := curSize

		// Obtain per-log delegation lease from Custodian.
		//
		// FOR-386: the requested range end is padded beyond the seal window so
		// one signed certificate covers subsequent seals until the log outgrows
		// it (the lease cache and on-chain publishCheckpoint are both
		// range-coverage checks, and the coordinator/lease verifications
		// exact-match against this request). Only the lease request widens —
		// the consistency proof and checkpoint below still bind the true
		// [mmrStart, curSize] window.
		lease, err := svc.LeaseManager.EnsureValidForLog(
			ctx,
			svc.HTTPClient,
			logger,
			svc.Cfg.DelegationKeyCurve,
			logIdHex,
			mmrStart,
			paddedRangeEnd(mmrEnd, svc.Cfg.DelegationRangePad),
		)
		if err != nil {
			return fmt.Errorf("failed to obtain delegation lease for log %s: %w", logIdHex, err)
		}
		coseSigner, kid, _, err := lease.COSESigner()
		if err != nil {
			return fmt.Errorf("delegation signer setup failed: %w", err)
		}

		// If the lease is expired or likely to expire during this run, abort so
		// the message can be retried and a fresh lease acquired.
		if time.Until(lease.ExpiresAt) < svc.LeaseManager.RenewBefore() {
			return ErrDelegationExpired
		}

		// Checkpoint format v3 (ADR-0046): emit a draft-bryce consistency
		// receipt from the previous checkpoint (baseState.MMRSize) to this seal
		// (curSize); the sealer signs the detached raw-concat payload with the
		// delegated key. Peak receipts are pre-signed with the same key so any
		// holder of the checkpoint and replicated log data can mint inclusion
		// receipts without the signing key. When the lease carries the
		// univocity on-chain delegation proof it rides the unprotected header
		// so the publisher can wire it into the publishCheckpoint calldata.
		proof, err := massifs.BuildConsistencyProof(&mc, baseState.MMRSize, curSize)
		if err != nil {
			return fmt.Errorf("build consistency proof (massif=%d): %w", mi, err)
		}
		signOpts := []massifs.CheckpointSignOption{massifs.WithPeakReceipts(kid)}
		extras := map[int64]cbor.RawMessage{}
		if len(lease.CertBytes) > 0 {
			rawCert, err := cbor.Marshal(lease.CertBytes)
			if err != nil {
				return fmt.Errorf("encode delegation certificate (massif=%d): %w", mi, err)
			}
			extras[delegationCertUnprotectedLabel] = rawCert
		}
		if lease.OnchainProof != nil {
			rawProof, err := canonicalCBOR.Marshal(lease.OnchainProof)
			if err != nil {
				return fmt.Errorf("encode onchain delegation proof (massif=%d): %w", mi, err)
			}
			extras[massifs.SealDelegationProofLabel] = rawProof
		}
		if len(extras) > 0 {
			signOpts = append(signOpts, massifs.WithUnprotectedExtras(extras))
		}
		receiptBytes, err := massifs.SignCheckpointReceipt(coseSigner, proof, newPeaks, signOpts...)
		if err != nil {
			return fmt.Errorf("sign checkpoint receipt (massif=%d): %w", mi, err)
		}

		// Write checkpoint with optimistic concurrency.
		if err := putCheckpoint(ctx, store, mi, curSize, receiptBytes); err != nil {
			return fmt.Errorf("write checkpoint (massif=%d): %w", mi, err)
		}

		observeCheckpointLag(svc, logger, &mc)

		// Advance base state.
		baseState.MMRSize = curSize
		baseState.Peaks = newPeaks
	}

	return nil
}

// paddedRangeEnd widens a delegation range end by pad MMR nodes, clamping on
// uint64 overflow (FOR-386 — see the EnsureValidForLog call site).
func paddedRangeEnd(mmrEnd, pad uint64) uint64 {
	if pad > ^uint64(0)-mmrEnd {
		return ^uint64(0)
	}
	return mmrEnd + pad
}

// observeCheckpointLag records sealer_checkpoint_lag_seconds for a just-written
// checkpoint: the time from the massif's last entry idtimestamp to now
// (ADR-0007 / FOR-379 — the trigger latency the seal-hint work targets).
// Best-effort: metric handles may be absent and the idtimestamp epoch must fit
// snowflakeid's uint8; either just skips the observation.
func observeCheckpointLag(svc SealerService, logger *slog.Logger, mc *massifs.MassifContext) {
	if svc.Metrics == nil {
		return
	}
	lastID := mc.GetLastIDTimestamp()
	if lastID == 0 {
		return
	}
	epoch := mc.Start.CommitmentEpoch
	if epoch > 255 {
		return
	}
	lastMS, err := snowflakeid.IDUnixMilli(lastID, uint8(epoch))
	if err != nil {
		logger.Debug("checkpoint lag: idtimestamp decode failed", "error", err)
		return
	}
	lag := time.Since(time.UnixMilli(lastMS)).Seconds()
	if lag < 0 {
		// Clock skew between the ranger's snowflake clock and ours; clamp
		// rather than feeding negatives to the histogram.
		lag = 0
	}
	svc.Metrics.ObserveCheckpointLag(lag)
}

func putCheckpoint(ctx context.Context, store *merklelog.Store, massifIndex uint32, mmrSize uint64, data []byte) error {
	const maxAttempts = 5

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Prefer create-only on first attempt.
		if attempt == 0 {
			err := store.Put(ctx, massifIndex, massifstorage.ObjectCheckpoint, data, true)
			if err == nil {
				return nil
			}
			if !errors.Is(err, massifstorage.ErrExistsOC) {
				return err
			}
		}

		// Read current object to get ETag and decide whether we still need to write.
		existing, err := store.CheckpointRead(ctx, massifIndex)
		if err != nil {
			if errors.Is(err, massifstorage.ErrDoesNotExist) {
				// Retry create-only.
				continue
			}
			return err
		}

		// If someone else already wrote a checkpoint at an equal-or-newer size, we can stop.
		if existingData, rerr := store.CheckpointRead(ctx, massifIndex); rerr == nil {
			if receipt, derr := massifs.DecodeCheckpointReceipt(existingData); derr == nil &&
				receipt.Proof.TreeSize2 >= mmrSize {
				return nil
			}
		}

		etag, ok, err := store.CheckpointETag(massifIndex)
		if err != nil {
			return err
		}
		if !ok || etag == "" {
			// This shouldn't happen because CheckpointRead cached it, but guard anyway.
			_ = existing
			return fmt.Errorf("missing etag for checkpoint %d after read", massifIndex)
		}

		err = store.PutWithETag(ctx, massifIndex, massifstorage.ObjectCheckpoint, data, false, etag)
		if err == nil {
			return nil
		}
		if errors.Is(err, massifstorage.ErrContentOC) {
			// ETag mismatch; retry.
			continue
		}
		return err
	}

	return fmt.Errorf("checkpoint write retries exceeded for massif %d", massifIndex)
}

func kidFromECDSAPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	if pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	uncompressed := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	sum := sha256.Sum256(uncompressed)
	kid := make([]byte, 16)
	copy(kid, sum[:16])
	return kid, nil
}
