package sealer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/fxamacker/cbor/v2"
)

// custodianSeedProvider derives the delegate-key seed via the custodian's
// POST /api/delegate-seed (KMS-MAC; ADR-0050 phase A). The seed is never at
// rest — it is re-derived at boot.
type custodianSeedProvider struct {
	baseURL    string
	token      string
	sealerID   string
	httpClient *HTTPClient
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
	return out.Seed, nil
}

// NewSeedProvider selects the seed source: the custodian KMS-MAC endpoint
// when a base URL is configured, else the local escape hatch (self-hosted).
func NewSeedProvider(cfg Config, httpClient *HTTPClient) (SeedProvider, error) {
	if cfg.DelegateSeedCustodianURL != "" {
		return custodianSeedProvider{
			baseURL:    cfg.DelegateSeedCustodianURL,
			token:      cfg.DelegateSeedCustodianToken,
			sealerID:   cfg.SealerID,
			httpClient: httpClient,
		}, nil
	}
	if len(cfg.DelegateSeedLocal) > 0 {
		return localSeedProvider{secret: cfg.DelegateSeedLocal}, nil
	}
	return nil, fmt.Errorf("no delegate seed source: set DELEGATE_SEED_CUSTODIAN_URL or DELEGATE_SEED")
}
