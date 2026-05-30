package sealer

import (
	"context"
	"errors"
	"fmt"
)

// SelectingTrustRootClient resolves trust roots from a primary HTTP service
// (typically delegation-coordinator public-root) and falls back to Custodian
// when the primary returns ErrTrustRootNotFound (HTTP 404).
type SelectingTrustRootClient struct {
	Primary  TrustRootClient
	Fallback TrustRootClient
}

func (c *SelectingTrustRootClient) LogSigningKey(
	ctx context.Context,
	logIdHex string,
) (LogSigningKey, error) {
	if c == nil {
		return LogSigningKey{}, fmt.Errorf("selecting trust root client is nil")
	}
	if c.Primary == nil {
		return LogSigningKey{}, fmt.Errorf("primary trust root client is nil")
	}
	if c.Fallback == nil {
		return LogSigningKey{}, fmt.Errorf("fallback trust root client is nil")
	}

	key, err := c.Primary.LogSigningKey(ctx, logIdHex)
	if err == nil {
		return key, nil
	}
	if errors.Is(err, ErrTrustRootNotFound) {
		return c.Fallback.LogSigningKey(ctx, logIdHex)
	}
	return LogSigningKey{}, err
}

// NewSelectingTrustRootClient wires production trust-root resolution: coordinator
// (or other HTTP public-root) first, Custodian public-key API on 404.
func NewSelectingTrustRootClient(cfg Config, httpClient *HTTPClient) TrustRootClient {
	primary := &HTTPTrustRootClient{
		BaseURL:    cfg.TrustRootURL,
		Token:      cfg.TrustRootToken,
		HTTPClient: httpClient,
	}
	fallbackURL := cfg.CustodianURL
	if fallbackURL == "" {
		fallbackURL = cfg.TrustRootURL
	}
	fallback := &CustodianPublicTrustRootClient{
		BaseURL:    fallbackURL,
		HTTPClient: httpClient,
	}
	return &SelectingTrustRootClient{
		Primary:  primary,
		Fallback: fallback,
	}
}
