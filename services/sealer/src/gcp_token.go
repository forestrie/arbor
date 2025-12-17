package sealer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/api/impersonate"
)

// DelegationSignerTokenInfo contains only non-sensitive details about an access token.
// Never log or return the token itself.
type DelegationSignerTokenInfo struct {
	TargetServiceAccount string
	TokenType            string
	Expiry               time.Time
	ExpiresIn            time.Duration
	TokenLength          int
	TokenFingerprint     string
}

// DelegationSignerAccessToken holds the access token plus safe metadata for logging.
// The AccessToken value is sensitive; do not log it.
type DelegationSignerAccessToken struct {
	AccessToken string
	Info        DelegationSignerTokenInfo
}

// AcquireDelegationSignerAccessToken impersonates the delegation-signer service account and
// fetches a single access token.
func AcquireDelegationSignerAccessToken(ctx context.Context, targetServiceAccountEmail string) (*DelegationSignerAccessToken, error) {
	target := targetServiceAccountEmail
	if target == "" {
		return nil, fmt.Errorf("target service account email is empty")
	}

	// Use ambient credentials (GKE Workload Identity) to call IAMCredentials and
	// mint an access token for the target service account.
	ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: target,
		Scopes:          []string{"https://www.googleapis.com/auth/cloud-platform"},
	})
	if err != nil {
		return nil, fmt.Errorf("create impersonated token source: %w", err)
	}

	tok, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("fetch impersonated access token: %w", err)
	}

	fingerprint := ""
	if tok.AccessToken != "" {
		sum := sha256.Sum256([]byte(tok.AccessToken))
		// Short fingerprint for logs (non-reversible, avoids log bloat).
		fingerprint = hex.EncodeToString(sum[:])[:16]
	}

	expiresIn := time.Duration(0)
	if !tok.Expiry.IsZero() {
		expiresIn = time.Until(tok.Expiry).Round(time.Second)
	}

	return &DelegationSignerAccessToken{
		AccessToken: tok.AccessToken,
		Info: DelegationSignerTokenInfo{
			TargetServiceAccount: target,
			TokenType:            tok.TokenType,
			Expiry:               tok.Expiry,
			ExpiresIn:            expiresIn,
			TokenLength:          len(tok.AccessToken),
			TokenFingerprint:     fingerprint,
		},
	}, nil
}
