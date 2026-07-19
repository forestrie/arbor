package sealer

import (
	"bytes"
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

	// Determine the latest existing checkpoint (if any). The head checkpoint
	// decides only where sealing resumes and whether the head massif has
	// grown since the last seal — it is NEVER the proof base. ADR-0056
	// (FOR-410): every checkpoint's base is its massif's entry boundary, so
	// replacing sth(a->b) with a seal at size c always yields sth(a->c) and
	// each massif's final retained checkpoint is a boundary-to-boundary
	// consistency link (the publisher's relay and offline chain verification
	// depend on this; seal-to-seal chaining was the FOR-410 drift bug).
	var startMassifIndex uint32 = 0
	var lastSealedSize uint64
	hasCheckpoint := false
	lastCheckpointIndex, err := store.HeadIndex(ctx, massifstorage.ObjectCheckpoint)
	switch {
	case errors.Is(err, massifstorage.ErrLogEmpty):
		// Start from scratch.
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
		hasCheckpoint = true
		// v3 checkpoint: the sealed size is the proof's tree-size-2.
		lastSealedSize = receipt.Proof.TreeSize2
	}

	// Process each massif from the last checkpoint to head. carried holds
	// the previous iteration's freshly computed accumulator for R1
	// cross-massif validation (nil on the first iteration: a same-massif
	// re-seal has no independent prior blob to validate against — see the
	// trust posture note on sealPlanForMassif).
	var carried *massifCarry
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

		plan, err := sealPlanForMassif(
			&mc,
			mi,
			lastSealedSize,
			hasCheckpoint && mi == lastCheckpointIndex,
			carried,
		)
		if err != nil {
			return err
		}
		if plan.skip {
			continue
		}
		curSize := plan.curSize
		baseState := plan.base
		newPeaks := plan.newPeaks

		// Calculate MMR range for this massif for the delegation
		// MMR size at start of massif and end of massif
		mmrStart := baseState.MMRSize
		mmrEnd := curSize

		// Obtain per-log delegation lease from Custodian.
		//
		// FOR-386: pass the TRUE seal window. The lease manager checks its
		// cache against this window (coverage) and pads only the ISSUANCE
		// request (DELEGATION_RANGE_PAD), so one signed certificate covers
		// subsequent seals until the log outgrows the pad. Padding the window
		// here instead would advance the requested end past the cached cert
		// on every append and defeat the cache by construction (the
		// first-cut #55 bug). The consistency proof and checkpoint below bind
		// this true window either way.
		lease, err := svc.LeaseManager.EnsureValidForLog(
			ctx,
			svc.HTTPClient,
			logger,
			svc.Cfg.DelegationKeyCurve,
			logIdHex,
			mmrStart,
			mmrEnd,
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
		// receipt from the massif entry boundary (plan.proof, ADR-0056) to
		// this seal (curSize); the sealer signs the detached raw-concat
		// payload with the delegated key. Peak receipts are pre-signed with
		// the same key so any holder of the checkpoint and replicated log
		// data can mint inclusion receipts without the signing key. When the
		// lease carries the univocity on-chain delegation proof it rides the
		// unprotected header so the publisher can wire it into the
		// publishCheckpoint calldata.
		proof := plan.proof
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

		// R1 (plan-2607-09): carry this massif's freshly computed
		// accumulator so the next massif in this run cross-validates its
		// ancestor peak stack against it.
		carried = &massifCarry{size: curSize, peaks: newPeaks}
	}

	return nil
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

// sealDecision is the per-massif checkpoint decision (ADR-0056 / FOR-410).
type sealDecision struct {
	// base is the consistency-proof base: ALWAYS the massif's entry
	// boundary, so replacing sth(a->b) with a re-seal at size c yields
	// sth(a->c) and each massif's final retained checkpoint is a
	// boundary-to-boundary link in the retained chain. It is never derived
	// from a prior checkpoint's tree-size-2 (the FOR-410 drift bug);
	// structural derivation also self-heals drifted legacy logs on their
	// next re-seal.
	base uint64
	// skip is true when the massif needs no (re-)seal.
	skip bool
}

// decideSeal chooses the checkpoint proof base and skip for one massif.
// entryBoundary is the massif's first MMR index (Start.FirstIndex), curSize
// the massif's current RangeCount, lastSealedSize the head checkpoint's
// tree-size-2 (0 when no checkpoint exists), and isHeadCheckpointMassif
// whether this massif is the one the head checkpoint covers.
func decideSeal(
	entryBoundary uint64,
	curSize uint64,
	lastSealedSize uint64,
	isHeadCheckpointMassif bool,
) sealDecision {
	if curSize == 0 {
		return sealDecision{skip: true}
	}
	if isHeadCheckpointMassif && curSize <= lastSealedSize {
		// No advance since the head checkpoint; nothing to re-seal.
		return sealDecision{skip: true}
	}
	return sealDecision{base: entryBoundary}
}

// massifCarry carries one massif's freshly computed accumulator across
// catch-up loop iterations so adjacent massif blobs cross-validate (R1,
// plan-2607-09): the next massif serves its ancestor peaks from its own
// peak stack, and those must byte-match the accumulator just computed from
// the previous massif's node data.
type massifCarry struct {
	size  uint64
	peaks [][]byte
}

// sealPlan is the computed checkpoint input for one massif.
type sealPlan struct {
	curSize  uint64
	base     massifs.MMRState
	newPeaks [][]byte
	proof    massifs.ConsistencyProof
	skip     bool
}

// sealPlanForMassif computes the checkpoint inputs for one massif: the
// skip decision, the entry-boundary base (ADR-0056), R1 cross-massif peak
// validation, the consistency-checked accumulator, and the boundary-based
// consistency proof. The boundary invariant is an internal-consistency
// guard across independently sourced facts: storage position (mi) must
// match the header's MassifIndex, and FirstIndex must match the boundary
// derived from the header's own height + index. The blob header is the
// replication-safe source; deployment-mutable config never feeds the
// boundary math (R4, plan-2607-09).
//
// Trust posture (R3, plan-2607-09): on a same-massif re-seal the boundary
// peaks are rehydrated from the massif's own ancestor peak stack, so the
// consistency check validates internal structure, not freshness relative
// to the previously signed checkpoint. Between-seal tamper evidence is the
// signed checkpoint chain plus external verifiers (ADR-0046) — never this
// local check. In catch-up runs, `carried` restores genuine cross-blob
// validation between adjacent massifs.
func sealPlanForMassif(
	mc *massifs.MassifContext,
	mi uint32,
	lastSealedSize uint64,
	isHeadCheckpointMassif bool,
	carried *massifCarry,
) (sealPlan, error) {
	curSize := mc.RangeCount()
	decision := decideSeal(
		mc.Start.FirstIndex,
		curSize,
		lastSealedSize,
		isHeadCheckpointMassif,
	)
	if decision.skip {
		return sealPlan{skip: true}, nil
	}

	// R4: internal consistency across independently sourced facts. The
	// blob header is the replication-safe, location-independent record
	// (config/path heights are deployment-mutable and never feed the
	// boundary math; the loop's path==header check fails closed on config
	// drift separately). Here the header must agree with the STORAGE
	// position (mi, from object enumeration), and FirstIndex must agree
	// with the boundary derived from the header's own height + index —
	// a single corrupted or forged field cannot silently move the base.
	if mc.Start.MassifIndex != mi {
		return sealPlan{}, fmt.Errorf(
			"massif header/storage position mismatch: header MassifIndex %d != object index %d (ADR-0056/FOR-410)",
			mc.Start.MassifIndex, mi,
		)
	}
	expectedBoundary := massifs.MassifFirstLeaf(mc.Start.MassifHeight, mi)
	if decision.base != expectedBoundary {
		return sealPlan{}, fmt.Errorf(
			"boundary invariant violated (massif=%d): header FirstIndex %d != entry boundary %d derived from header height %d (ADR-0056/FOR-410)",
			mi, decision.base, expectedBoundary, mc.Start.MassifHeight,
		)
	}

	baseState := massifs.MMRState{MMRSize: decision.base}
	var newPeaks [][]byte
	if baseState.MMRSize == 0 {
		peaks, err := mmr.PeakHashes(mc, curSize-1)
		if err != nil {
			return sealPlan{}, fmt.Errorf("compute peaks: %w", err)
		}
		newPeaks = peaks
	} else {
		basePeaks, err := mmr.PeakHashes(mc, baseState.MMRSize-1)
		if err != nil {
			return sealPlan{}, fmt.Errorf(
				"rehydrate boundary peaks (massif=%d): %w", mi, err)
		}
		// R1: when the previous massif in this run ended exactly at this
		// boundary, its just-computed accumulator must byte-match the peak
		// stack this massif serves — or one of the adjacent blobs is wrong.
		if carried != nil && carried.size == baseState.MMRSize {
			if err := requireEqualPeaks(carried.peaks, basePeaks); err != nil {
				return sealPlan{}, fmt.Errorf(
					"cross-massif validation failed (massif=%d): %w (R1, plan-2607-09)",
					mi, err)
			}
		}
		baseState.Peaks = basePeaks
		peaks, err := mc.CheckConsistency(baseState)
		if err != nil {
			return sealPlan{}, fmt.Errorf(
				"consistency check (massif=%d): %w", mi, err)
		}
		if peaks == nil {
			// Massif holds no entries past its own boundary.
			return sealPlan{skip: true}, nil
		}
		newPeaks = peaks
	}

	proof, err := massifs.BuildConsistencyProof(mc, baseState.MMRSize, curSize)
	if err != nil {
		return sealPlan{}, fmt.Errorf(
			"build consistency proof (massif=%d): %w", mi, err)
	}
	// ADR-0056 invariant enforcement: never emit a checkpoint whose proof
	// base is not the independently derived entry boundary.
	if proof.TreeSize1 != expectedBoundary {
		return sealPlan{}, fmt.Errorf(
			"boundary invariant violated (massif=%d): proof base %d != entry boundary %d (ADR-0056/FOR-410)",
			mi, proof.TreeSize1, expectedBoundary,
		)
	}
	return sealPlan{
		curSize:  curSize,
		base:     baseState,
		newPeaks: newPeaks,
		proof:    proof,
	}, nil
}

// requireEqualPeaks compares two accumulators byte-for-byte.
func requireEqualPeaks(carried, rehydrated [][]byte) error {
	if len(carried) != len(rehydrated) {
		return fmt.Errorf(
			"accumulator length mismatch: carried %d peaks, peak stack serves %d",
			len(carried), len(rehydrated))
	}
	for i := range carried {
		if !bytes.Equal(carried[i], rehydrated[i]) {
			return fmt.Errorf("peak %d differs between carried accumulator and peak stack", i)
		}
	}
	return nil
}
