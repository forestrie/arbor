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

// StartDelegateKeysWithRetry loads the standing delegate keys at boot, wires
// them into the lease manager, and returns the readiness /readyz reports.
// When DELEGATE_KEY_EPOCH>=1 the custodian is REQUIRED (there is no on-demand
// degrade), so a failed load retries with backoff in the background rather
// than exiting, letting the sealer and custodian start in any order (ADR-0050
// boot posture, phase J1). The first attempt runs inline so a healthy
// custodian wires keys before the queue consumer starts.
//
// After install, readiness waits for the coordinator to report the current
// key registered on every shard, and the seeds are reloaded daily so the
// custodian keeps the registration fresh (devdocs plan-2609-12 slice 05; see
// delegate_readiness.go).
func StartDelegateKeysWithRetry(
	ctx context.Context,
	httpClient *HTTPClient,
	logger *slog.Logger,
	cfg Config,
	leaseMgr *DelegationLeaseManager,
	gauge DelegateKeyRegisteredGauge,
) *DelegateKeyReadiness {
	if cfg.DelegateKeyEpoch == 0 {
		logger.Info("delegation-in-advance explicitly disabled (DELEGATE_KEY_EPOCH=0)")
		return &DelegateKeyReadiness{disabled: true}
	}
	r := &delegateKeyRunner{
		logger:    logger,
		epoch:     cfg.DelegateKeyEpoch,
		readiness: &DelegateKeyReadiness{},
		gauge:     gauge,
		load: func(ctx context.Context) (*DelegateKeySet, error) {
			return StartDelegateKeySchedule(ctx, httpClient, logger, cfg)
		},
		install:            leaseMgr.SetDelegateKeys,
		loadBackoffStart:   delegateSeedRetryBackoffStart,
		loadBackoffMax:     delegateSeedRetryBackoffMax,
		lookupBackoffStart: delegateKeyLookupBackoffStart,
		lookupBackoffMax:   delegateKeyLookupBackoffMax,
		warnAfter:          delegateKeyUnregisteredWarnAfter,
		reloadInterval:     delegateKeyReloadInterval,
		now:                time.Now,
	}
	if cfg.DelegateSeedCustodianURL != "" {
		// Only custodian-derived keys are registered (with a voucher); the
		// sealer observes that registration through the coordinator.
		r.lookup = coordinatorDelegateKeyLookup{
			baseURL:    cfg.CoordinatorRegisterURL,
			token:      cfg.CoordinatorRegisterToken,
			httpClient: httpClient,
		}.Registered
		// Export 0 from boot so "registered == 0 for 15 min" also catches a
		// sealer that never gets as far as installing keys.
		gauge.SetDelegateKeyRegistered(cfg.DelegateKeyEpoch, false)
	}
	keys, err := r.load(ctx)
	if err != nil {
		r.logLoadFailure(err)
	} else {
		r.installKeys(keys)
	}
	go r.run(ctx, keys)
	return r.readiness
}

// StartDelegateKeySchedule loads the sealer's standing delegate keys (epoch N
// and N-1) for the seal hot path. The sealer holds only the private keys and
// signs checkpoints with them; it does NOT register them with the coordinator —
// the custodian registers the standing key + a signed voucher at seed issuance
// (FOR-390 phase G3), so registration carries a verifiable binding to the
// sealer identity and a compromised app-token cannot inject a rogue key.
//
// Returns nil when the feature is off (DelegateKeyEpoch == 0) so callers can
// gate hot-path behaviour on a non-nil key set. Runs at boot and on the daily
// reload; nothing here touches the per-seal path.
func StartDelegateKeySchedule(ctx context.Context, httpClient *HTTPClient, logger *slog.Logger, cfg Config) (*DelegateKeySet, error) {
	if cfg.DelegateKeyEpoch == 0 {
		logger.Info("delegation-in-advance explicitly disabled (DELEGATE_KEY_EPOCH=0)")
		return nil, nil
	}
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
