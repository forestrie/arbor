package sealer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/fxamacker/cbor/v2"
)

// errDelegateSeedEpochRetired reports the custodian's 409: the KMS MAC key
// version named by the epoch is disabled or gone, so the epoch can never be
// derived again (plan-2609-11: the epoch IS the key version number). It is
// final for this boot, unlike a transport or 5xx failure which is retried.
var errDelegateSeedEpochRetired = errors.New("delegate seed epoch retired")

// custodianSeedProvider derives the delegate-key seed via the custodian's
// POST /api/delegate-seed (KMS-MAC; ADR-0050 phase A). The seed is never at
// rest — it is re-derived at boot.
type custodianSeedProvider struct {
	baseURL    string
	token      string
	sealerID   string
	httpClient *HTTPClient
	logger     *slog.Logger // optional; logs the KMS key version each seed derived under
}

type delegateSeedRequest struct {
	SealerID string `cbor:"sealerId"`
	Epoch    uint32 `cbor:"epoch"`
}

type delegateSeedResponse struct {
	Seed          []byte `cbor:"seed"`
	KMSKeyVersion string `cbor:"kmsKeyVersion"`
}

func (p custodianSeedProvider) Seed(ctx context.Context, epoch uint32) ([]byte, error) {
	body, err := cbor.Marshal(delegateSeedRequest{SealerID: p.sealerID, Epoch: epoch})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, p.baseURL+"/api/delegate-seed", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("Accept", "application/cbor")

	resp, err := p.httpClient.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("delegate-seed request: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("%w: epoch %d (custodian status=409)", errDelegateSeedEpochRetired, epoch)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("delegate-seed status=%d", resp.StatusCode)
	}
	var out delegateSeedResponse
	if err := cbor.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("decode delegate-seed response: %w", err)
	}
	if len(out.Seed) == 0 {
		return nil, fmt.Errorf("delegate-seed response missing seed")
	}
	if p.logger != nil {
		// Makes a key-version rotation visible in the boot log: epoch N under
		// version N and epoch N-1 under version N-1.
		p.logger.Info("delegate seed derived", "epoch", epoch, "kmsKeyVersion", out.KMSKeyVersion)
	}
	return out.Seed, nil
}

// NewSeedProvider selects the seed source: the custodian KMS-MAC endpoint
// when a base URL is configured, else the local escape hatch (self-hosted).
func NewSeedProvider(cfg Config, httpClient *HTTPClient) (SeedProvider, error) {
	return newSeedProvider(cfg, httpClient, nil)
}

func newSeedProvider(cfg Config, httpClient *HTTPClient, logger *slog.Logger) (SeedProvider, error) {
	if cfg.DelegateSeedCustodianURL != "" {
		return custodianSeedProvider{
			baseURL:    cfg.DelegateSeedCustodianURL,
			token:      cfg.DelegateSeedCustodianToken,
			sealerID:   cfg.SealerID,
			httpClient: httpClient,
			logger:     logger,
		}, nil
	}
	if len(cfg.DelegateSeedLocal) > 0 {
		return localSeedProvider{secret: cfg.DelegateSeedLocal}, nil
	}
	return nil, fmt.Errorf("no delegate seed source: set DELEGATE_SEED_CUSTODIAN_URL or DELEGATE_SEED")
}
