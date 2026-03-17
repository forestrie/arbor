package custodian

import (
	"context"
	"time"

	"google.golang.org/api/impersonate"
)

// ShortLivedToken holds an access token and expiry for API responses.
type ShortLivedToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"` // seconds
}

// AcquireToken impersonates the given service account and returns a short-lived token.
func (a *API) AcquireToken(ctx context.Context, targetSA string) (*ShortLivedToken, error) {
	if targetSA == "" {
		return nil, ErrTargetSAEmpty
	}
	ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: targetSA,
		Scopes:          []string{"https://www.googleapis.com/auth/cloud-platform"},
	})
	if err != nil {
		return nil, err
	}
	tok, err := ts.Token()
	if err != nil {
		return nil, err
	}
	expiresIn := 0
	if !tok.Expiry.IsZero() {
		expiresIn = int(time.Until(tok.Expiry).Seconds())
		if expiresIn < 0 {
			expiresIn = 0
		}
	}
	return &ShortLivedToken{
		AccessToken: tok.AccessToken,
		ExpiresIn:   expiresIn,
	}, nil
}
