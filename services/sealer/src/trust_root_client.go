package sealer

import (
	"context"
	"fmt"
)

// LogSigningKey is the expected log signing (trust-root) public key material.
type LogSigningKey struct {
	PublicKeyPEM string // ES256 SPKI PEM (empty for KS256)
	Alg          string // "ES256" | "KS256"
	AlgInt       int64  // COSE alg (-7 | -65799)
	KS256Signer  []byte // 20-byte address when Alg is KS256
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
