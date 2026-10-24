package sealer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

const (
	delegateSeedRetryBackoffStart = time.Second
	delegateSeedRetryBackoffMax   = 30 * time.Second
)

// StartDelegateKeysWithRetry loads the standing delegate keys at boot and
// installs them in the lease manager. The custodian (or the local seed) is
// required: there is no on-demand fallback (devdocs plan-2609-12 slice 10).
// On failure it retries with backoff in the background rather than exiting,
// so the sealer and custodian start in any order (ADR-0050 boot posture,
// phase J1). The first attempt runs inline, so a healthy seed source installs
// keys before this returns. installed fires once keys are installed; main
// serves /readyz from it and starts consuming only then.
func StartDelegateKeysWithRetry(
	ctx context.Context,
	httpClient *HTTPClient,
	logger *slog.Logger,
	cfg Config,
	leaseMgr *DelegationLeaseManager,
	installed *DelegateKeysInstalled,
) {
	load := func() (*DelegateKeySet, error) {
		return StartDelegateKeySchedule(ctx, httpClient, logger, cfg)
	}
	startDelegateKeys(
		ctx, logger, load, leaseMgr, installed,
		delegateSeedRetryBackoffStart, delegateSeedRetryBackoffMax,
	)
}

// startDelegateKeys is StartDelegateKeysWithRetry with the load and backoff
// seams exposed for unit testing.
func startDelegateKeys(
	ctx context.Context,
	logger *slog.Logger,
	load func() (*DelegateKeySet, error),
	leaseMgr *DelegationLeaseManager,
	installed *DelegateKeysInstalled,
	backoffStart, backoffMax time.Duration,
) {
	onReady := func(keys *DelegateKeySet) {
		leaseMgr.SetDelegateKeys(keys)
		installed.fire()
		logger.Warn("delegation-in-advance enabled", "delegate_key_epoch", keys.currentEpoch)
	}
	keys, err := loadKeys(load)
	if err == nil {
		onReady(keys)
		return
	}
	logger.Warn("delegate key schedule not ready at boot (retrying in background)", "error", err)
	go loadDelegateKeysWithRetry(ctx, logger, load, onReady, backoffStart, backoffMax)
}

// loadDelegateKeysWithRetry retries load with exponential backoff until it
// succeeds or ctx is cancelled, invoking onReady once on success. Extracted for
// unit testing; startDelegateKeys runs it in a goroutine.
func loadDelegateKeysWithRetry(
	ctx context.Context,
	logger *slog.Logger,
	load func() (*DelegateKeySet, error),
	onReady func(*DelegateKeySet),
	backoffStart, backoffMax time.Duration,
) {
	backoff := backoffStart
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		keys, err := loadKeys(load)
		if err == nil {
			onReady(keys)
			return
		}
		logger.Warn("delegate key schedule not ready (will retry)", "error", err)
		backoff = min(backoff*2, backoffMax)
	}
}

// loadKeys runs load and treats a successful load with no keys as a failure,
// so the installed gate can never open without keys.
func loadKeys(load func() (*DelegateKeySet, error)) (*DelegateKeySet, error) {
	keys, err := load()
	if err == nil && keys == nil {
		err = errors.New("delegate key load returned no keys")
	}
	return keys, err
}

// StartDelegateKeySchedule loads the sealer's standing delegate keys (epoch N
// and N-1) for the seal hot path. The sealer holds only the private keys and
// signs checkpoints with them; it does NOT register them with the coordinator —
// the custodian registers the standing key + a signed voucher at seed issuance
// (FOR-390 phase G3), so registration carries a verifiable binding to the
// sealer identity and a compromised app-token cannot inject a rogue key.
//
// Boot-time only; nothing here touches the per-seal path. On success the key
// set is never nil.
func StartDelegateKeySchedule(ctx context.Context, httpClient *HTTPClient, logger *slog.Logger, cfg Config) (*DelegateKeySet, error) {
	provider, err := newSeedProvider(cfg, httpClient, logger)
	if err != nil {
		return nil, fmt.Errorf("delegate seed provider: %w", err)
	}
	keys, err := LoadDelegateKeys(ctx, provider, cfg.DelegateKeyEpoch)
	if err != nil {
		return nil, fmt.Errorf("load delegate keys: %w", err)
	}
	if keys.PreviousRetired() {
		logger.Warn("previous delegate epoch retired by the custodian; running with the current epoch only",
			"epoch", cfg.DelegateKeyEpoch,
			"retiredEpoch", cfg.DelegateKeyEpoch-1,
		)
	}
	currentHash, err := pubkeyHashHex(&keys.Current().PublicKey)
	if err != nil {
		return nil, fmt.Errorf("hash current delegate key: %w", err)
	}
	logger.Info("delegate keys loaded",
		"epoch", cfg.DelegateKeyEpoch,
		"keys", len(keys.entries),
		"currentPubkeyHash", currentHash,
	)
	return keys, nil
}
