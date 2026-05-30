package sealer

import (
	"context"
	"fmt"
)

// LogSigningKey is the expected log signing (trust-root) public key material.
type LogSigningKey struct {
	PublicKeyPEM string
	Alg          string
}

// TrustRootClient reads the expected log signing key for delegation verification.
type TrustRootClient interface {
	LogSigningKey(ctx context.Context, logIdHex string) (LogSigningKey, error)
}

// CustodianPublicTrustRootClient resolves trust roots via Custodian GET public key.
type CustodianPublicTrustRootClient struct {
	BaseURL    string
	HTTPClient *HTTPClient
}

func (c *CustodianPublicTrustRootClient) LogSigningKey(
	ctx context.Context,
	logIdHex string,
) (LogSigningKey, error) {
	if c == nil || c.HTTPClient == nil {
		return LogSigningKey{}, fmt.Errorf("trust root client not configured")
	}
	pem, alg, err := GetPublicKeyByLogID(ctx, c.HTTPClient, c.BaseURL, logIdHex)
	if err != nil {
		return LogSigningKey{}, err
	}
	return LogSigningKey{PublicKeyPEM: pem, Alg: alg}, nil
}
