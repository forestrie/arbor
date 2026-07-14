package sealer

import (
	"context"
	"fmt"
	"log/slog"
)

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
		logger.Info("delegation-in-advance disabled (DELEGATE_KEY_EPOCH=0)")
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
