package sealer

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

const (
	delegateSeedRetryBackoffStart = time.Second
	delegateSeedRetryBackoffMax   = 30 * time.Second
)

// StartDelegateKeysWithRetry loads the standing delegate keys at boot and wires
// them into the lease manager. When DELEGATE_KEY_EPOCH>=1 the custodian is
// REQUIRED (there is no on-demand degrade), so on failure this retries with
// backoff in the background rather than exiting or silently continuing without
// keys — letting the sealer and custodian start in any order (ADR-0050 boot
// posture, phase J1). Non-blocking: the first attempt runs inline (so a healthy
// custodian wires keys before the queue consumer starts); a failing first
// attempt hands off to a background retry while the sealer serves liveness.
func StartDelegateKeysWithRetry(
	ctx context.Context,
	httpClient *HTTPClient,
	logger *slog.Logger,
	cfg Config,
	leaseMgr *DelegationLeaseManager,
) {
	if cfg.DelegateKeyEpoch == 0 {
		logger.Info("delegation-in-advance explicitly disabled (DELEGATE_KEY_EPOCH=0)")
		return
	}
	load := func() (*DelegateKeySet, error) {
		return StartDelegateKeySchedule(ctx, httpClient, logger, cfg)
	}
	onReady := func(keys *DelegateKeySet) {
		leaseMgr.SetDelegateKeys(keys)
		logger.Warn("delegation-in-advance enabled", "delegate_key_epoch", cfg.DelegateKeyEpoch)
	}
	if keys, err := load(); err == nil {
		if keys != nil {
			onReady(keys)
		}
		return
	} else {
		logger.Warn("delegate key schedule not ready at boot (retrying in background)", "error", err)
	}
	go loadDelegateKeysWithRetry(
		ctx, logger, load, onReady,
		delegateSeedRetryBackoffStart, delegateSeedRetryBackoffMax,
	)
}

// loadDelegateKeysWithRetry retries load with exponential backoff until it
// succeeds or ctx is cancelled, invoking onReady once on success. Extracted for
// unit testing; StartDelegateKeysWithRetry runs it in a goroutine.
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
		keys, err := load()
		if err == nil {
			if keys != nil {
				onReady(keys)
			}
			return
		}
		logger.Warn("delegate key schedule not ready (will retry)", "error", err)
		backoff = min(backoff*2, backoffMax)
	}
}

// StartDelegateKeySchedule loads the sealer's standing delegate keys (epoch N
// and N-1) for the seal hot path. The sealer holds only the private keys and
// signs checkpoints with them; it does NOT register them with the coordinator —
// the custodian registers the standing key + a signed voucher at seed issuance
// (FOR-390 phase G3), so registration carries a verifiable binding to the
// sealer identity and a compromised app-token cannot inject a rogue key.
//
// Returns nil when the feature is off (DelegateKeyEpoch == 0) so callers can
// gate hot-path behaviour on a non-nil key set. Boot-time only; nothing here
// touches the per-seal path.
func StartDelegateKeySchedule(ctx context.Context, httpClient *HTTPClient, logger *slog.Logger, cfg Config) (*DelegateKeySet, error) {
	if cfg.DelegateKeyEpoch == 0 {
		logger.Info("delegation-in-advance explicitly disabled (DELEGATE_KEY_EPOCH=0)")
		return nil, nil
	}
	provider, err := NewSeedProvider(cfg, httpClient)
	if err != nil {
		return nil, fmt.Errorf("delegate seed provider: %w", err)
	}
	keys, err := LoadDelegateKeys(ctx, provider, cfg.DelegateKeyEpoch)
	if err != nil {
		return nil, fmt.Errorf("load delegate keys: %w", err)
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
