package sealer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// DelegateKeyRegistration is the JSON body for POST /api/sealer/delegate-keys
// (plan-2607-20 phase C). It advertises the sealer's current standing
// delegate key so the coordinator can pre-issue advance certificates bound to
// it. It carries no private material; the public key alone lets the
// coordinator build and sign certificates + on-chain proofs.
type DelegateKeyRegistration struct {
	SealerID           string `json:"sealerId"`
	Epoch              uint32 `json:"epoch"`
	Algorithm          string `json:"algorithm"`
	DelegatedPublicKey string `json:"delegatedPublicKey"` // hex(x||y), 128 hex chars
	DelegatedPubkeyHash string `json:"delegatedPubkeyHash"` // hex(sha256(uncompressed point))
}

// registerDelegateKey advertises the current delegate key to the coordinator.
// It is best-effort: a failure is logged and swallowed so it never blocks
// sealer boot. The coordinator can also learn the key lazily at issuance time,
// so registration is an optimization, not a correctness dependency.
func registerDelegateKey(ctx context.Context, httpClient *HTTPClient, logger *slog.Logger, cfg Config, pub *ecdsa.PublicKey) {
	if cfg.CoordinatorRegisterURL == "" {
		logger.Info("delegate key registration skipped: no coordinator URL")
		return
	}
	reg := DelegateKeyRegistration{
		SealerID:            cfg.SealerID,
		Epoch:               cfg.DelegateKeyEpoch,
		Algorithm:           "ES256",
		DelegatedPublicKey:  hex.EncodeToString(pubkeyXYBytes(pub)),
		DelegatedPubkeyHash: pubkeyHashHex(pub),
	}
	body, err := json.Marshal(reg)
	if err != nil {
		logger.Warn("delegate key registration: marshal failed", "error", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, cfg.CoordinatorRegisterURL+"/api/sealer/delegate-keys", bytes.NewReader(body))
	if err != nil {
		logger.Warn("delegate key registration: build request failed", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.CoordinatorRegisterToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.CoordinatorRegisterToken)
	}

	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		logger.Warn("delegate key registration failed (best-effort)", "error", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		logger.Warn("delegate key registration rejected (best-effort)",
			"status", resp.StatusCode, "pubkeyHash", reg.DelegatedPubkeyHash)
		return
	}
	logger.Info("delegate key registered with coordinator",
		"sealerId", reg.SealerID, "epoch", reg.Epoch, "pubkeyHash", reg.DelegatedPubkeyHash)
}

// StartDelegateKeySchedule loads standing delegate keys (epoch N and N-1) and
// advertises the current one to the coordinator. Returns nil when the feature
// is off (DelegateKeyEpoch == 0) so callers can gate hot-path behaviour on a
// non-nil key set. All work here is boot-time only; nothing touches the
// per-seal path in this phase (plan-2607-20 phase B — additive).
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
	logger.Info("delegate keys loaded",
		"epoch", cfg.DelegateKeyEpoch,
		"currentPubkeyHash", pubkeyHashHex(&keys.Current().PublicKey),
	)
	registerDelegateKey(ctx, httpClient, logger, cfg, &keys.Current().PublicKey)
	return keys, nil
}
