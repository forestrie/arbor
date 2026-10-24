package sealer

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// StartDelegateKeysWithRetry loads the standing delegate keys, installs them
// in the lease manager, and keeps their registration with the coordinator
// asserted (devdocs plan-2609-12 slice 05; see delegate_key_runner.go). The
// custodian (or the test-only local seed) is required: there is no
// on-demand fallback (slice 10). A failed load retries in the background
// rather than exiting, so the sealer and custodian start in any order
// (ADR-0050 boot posture, phase J1). The first attempt runs inline, so a
// healthy seed source installs keys before this returns.
//
// readiness latches once keys are installed and the current key's first
// assertion succeeded; main serves /readyz from it and starts consuming only
// then. gauge receives sealer_delegate_key_registered.
func StartDelegateKeysWithRetry(
	ctx context.Context,
	httpClient *HTTPClient,
	logger *slog.Logger,
	cfg Config,
	leaseMgr *DelegationLeaseManager,
	readiness *DelegateKeyReadiness,
	gauge DelegateKeyRegisteredGauge,
) {
	newDelegateKeyRunner(cfg, httpClient, logger, leaseMgr, readiness, gauge).start(ctx)
}

// newDelegateKeyRunner wires the runner with production timings. Assertion
// is enabled exactly when the selected seed provider is the custodian, the
// only source of vouchers (slice 05 change 9).
func newDelegateKeyRunner(
	cfg Config,
	httpClient *HTTPClient,
	logger *slog.Logger,
	leaseMgr *DelegationLeaseManager,
	readiness *DelegateKeyReadiness,
	gauge DelegateKeyRegisteredGauge,
) *delegateKeyRunner {
	r := &delegateKeyRunner{
		logger:             logger,
		sealerID:           cfg.SealerID,
		epoch:              cfg.DelegateKeyEpoch,
		readiness:          readiness,
		gauge:              gauge,
		install:            leaseMgr.SetDelegateKeys,
		loadBackoffStart:   delegateSeedRetryBackoffStart,
		loadBackoffMax:     delegateSeedRetryBackoffMax,
		assertInterval:     delegateKeyAssertInterval,
		assertJitter:       delegateKeyAssertJitter,
		assertBackoffStart: delegateKeyAssertBackoffStart,
		assertBackoffMax:   delegateKeyAssertBackoffMax,
		registeredFor:      delegateKeyRegisteredFor,
		warnLogEvery:       delegateKeyWarnLogInterval,
		refreshAfter:       voucherRefreshAfter,
		refreshRetryAfter:  voucherRefreshRetryAfter,
		now:                time.Now,
	}
	provider, err := newSeedProvider(cfg, httpClient, logger)
	if err != nil {
		// Config validation refuses this; hold readiness if it gets here.
		r.load = func(context.Context) (*DelegateKeySet, error) {
			return nil, fmt.Errorf("delegate seed provider: %w", err)
		}
		return r
	}
	r.load = func(ctx context.Context) (*DelegateKeySet, error) {
		return loadStandingKeys(ctx, logger, provider, cfg.DelegateKeyEpoch)
	}
	if _, ok := provider.(custodianSeedProvider); ok {
		r.assert = coordinatorDelegateKeyRegistrar{
			baseURL:    cfg.CoordinatorRegisterURL,
			token:      cfg.CoordinatorRegisterToken,
			httpClient: httpClient,
		}.assert
	}
	return r
}

// loadStandingKeys loads the sealer's standing delegate keys (epoch N and
// N-1) and, from the custodian, their vouchers. It runs at boot and on each
// voucher refresh; nothing here touches the per-seal path. On success the
// key set is never nil.
func loadStandingKeys(ctx context.Context, logger *slog.Logger, provider SeedProvider, epoch uint32) (*DelegateKeySet, error) {
	keys, err := LoadDelegateKeys(ctx, provider, epoch)
	if err != nil {
		return nil, fmt.Errorf("load delegate keys: %w", err)
	}
	if keys.PreviousRetired() {
		logger.Warn("previous delegate epoch retired by the custodian; running with the current epoch only",
			"epoch", epoch,
			"retiredEpoch", epoch-1,
		)
	}
	logger.Info("delegate keys loaded",
		"epoch", epoch,
		"keys", len(keys.entries),
		"currentPubkeyHash", keys.entries[0].pubkeyHash,
	)
	return keys, nil
}
