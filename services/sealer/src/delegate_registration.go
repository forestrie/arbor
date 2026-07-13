package sealer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// DelegateKeyEntry is one standing key in a registration (plan-2607-20 phase
// C, shape C1). PublicKey is the canonical COSE_Key CBOR (base64) — the same
// bytes a signer binds into a certificate, so the coordinator's
// sha256(publicKey) equals the certificate's delegated_pubkey_hash.
type DelegateKeyEntry struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"publicKey"` // base64(COSE_Key CBOR)
	Epoch     uint32 `json:"epoch"`
	NotAfter  int64  `json:"notAfter"` // unix seconds; retired past this
}

// DelegateKeyRegistration is the JSON body for POST /api/sealer/delegate-keys.
// It advertises the sealer's standing delegate keys (epoch N and N-1) so the
// coordinator can pre-issue advance certificates bound to them across a
// rotation. It carries no private material.
type DelegateKeyRegistration struct {
	SealerID string             `json:"sealerId"`
	Keys     []DelegateKeyEntry `json:"keys"`
}

// registerDelegateKeys advertises the sealer's standing delegate keys (N and
// N-1) to the coordinator. Best-effort: a failure is logged and swallowed so
// it never blocks sealer boot. Both epochs are registered with a
// rotation-spanning notAfter so a certificate bound to the previous epoch's
// key keeps issuing until its own expiry (review F2).
func registerDelegateKeys(ctx context.Context, httpClient *HTTPClient, logger *slog.Logger, cfg Config, keys *DelegateKeySet, nowUnix int64) {
	if cfg.CoordinatorRegisterURL == "" {
		logger.Info("delegate key registration skipped: no coordinator URL")
		return
	}
	notAfter := nowUnix + int64(cfg.DelegateKeyTTL.Seconds())
	reg := DelegateKeyRegistration{SealerID: cfg.SealerID}
	for _, entry := range keys.entries {
		coseKey, err := delegateCoseKeyBytes(&entry.priv.PublicKey)
		if err != nil {
			logger.Warn("delegate key registration: encode failed", "epoch", entry.epoch, "error", err)
			return
		}
		reg.Keys = append(reg.Keys, DelegateKeyEntry{
			Alg:       "ES256",
			PublicKey: base64.StdEncoding.EncodeToString(coseKey),
			Epoch:     entry.epoch,
			NotAfter:  notAfter,
		})
	}
	if len(reg.Keys) == 0 {
		logger.Warn("delegate key registration skipped: no keys loaded")
		return
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
			"status", resp.StatusCode, "sealerId", reg.SealerID, "keys", len(reg.Keys))
		return
	}
	logger.Info("delegate keys registered with coordinator",
		"sealerId", reg.SealerID, "keys", len(reg.Keys), "notAfter", notAfter)
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
	currentHash, err := pubkeyHashHex(&keys.Current().PublicKey)
	if err != nil {
		return nil, fmt.Errorf("hash current delegate key: %w", err)
	}
	logger.Info("delegate keys loaded",
		"epoch", cfg.DelegateKeyEpoch,
		"keys", len(keys.entries),
		"currentPubkeyHash", currentHash,
	)
	registerDelegateKeys(ctx, httpClient, logger, cfg, keys, time.Now().Unix())
	return keys, nil
}
