package sealer

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// AuthorizeBinding is the univocity trust decision for a delegation certificate.
type AuthorizeBinding struct {
	Authorized      bool
	SigningKey      LogSigningKey
	RootLogIDHex    string
	ChainID         string
	ContractAddress string
	Source          string
}

// AuthorizeClient asks the trusted univocity service whether a delegation
// certificate is signed by the authorized key for its log, returning the
// authoritative root key and chain binding.
type AuthorizeClient interface {
	Authorize(ctx context.Context, certBytes []byte, logIdHex string) (AuthorizeBinding, error)
}

// authorizeRequest mirrors univocity's POST /api/authorize CBOR input.
type authorizeRequest struct {
	Certificate []byte `cbor:"certificate"`
	LogID       []byte `cbor:"logId,omitempty"`
}

// authorizeResponse mirrors univocity's POST /api/authorize CBOR output.
type authorizeResponse struct {
	Authorized bool   `cbor:"authorized"`
	LogID      []byte `cbor:"logId,omitempty"`
	RootLogID  []byte `cbor:"rootLogId,omitempty"`
	Alg        string `cbor:"alg,omitempty"`
	X          []byte `cbor:"x,omitempty"`
	Y          []byte `cbor:"y,omitempty"`
	ChainID    string `cbor:"chainId,omitempty"`
	Contract   string `cbor:"contract,omitempty"`
	Source     string `cbor:"source,omitempty"`
}

// HTTPAuthorizeClient calls univocity POST {BaseURL}/api/authorize.
type HTTPAuthorizeClient struct {
	BaseURL    string
	Token      string
	HTTPClient *HTTPClient
}

// Authorize posts the (untrusted) certificate to univocity. A 401 returns a
// binding with Authorized=false (no error) so callers fail closed cleanly.
func (c *HTTPAuthorizeClient) Authorize(
	ctx context.Context,
	certBytes []byte,
	logIdHex string,
) (AuthorizeBinding, error) {
	if c == nil || c.HTTPClient == nil {
		return AuthorizeBinding{}, fmt.Errorf("authorize client not configured")
	}
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		return AuthorizeBinding{}, fmt.Errorf("authorize base URL is empty")
	}
	if len(certBytes) == 0 {
		return AuthorizeBinding{}, fmt.Errorf("certificate is empty")
	}

	reqBody, err := cbor.Marshal(authorizeRequest{Certificate: certBytes})
	if err != nil {
		return AuthorizeBinding{}, fmt.Errorf("encode authorize request: %w", err)
	}
	endpoint := base + "/api/authorize"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return AuthorizeBinding{}, fmt.Errorf("build authorize request: %w", err)
	}
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("Accept", "application/cbor")
	if token := strings.TrimSpace(c.Token); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.HTTPClient.Do(ctx, req)
	if err != nil {
		return AuthorizeBinding{}, fmt.Errorf("authorize request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return AuthorizeBinding{}, fmt.Errorf("read authorize response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusUnauthorized:
		return AuthorizeBinding{Authorized: false}, nil
	default:
		return AuthorizeBinding{}, fmt.Errorf(
			"authorize returned status=%d for log %s", resp.StatusCode, logIdHex,
		)
	}

	var record authorizeResponse
	if err := cbor.Unmarshal(body, &record); err != nil {
		return AuthorizeBinding{}, fmt.Errorf("decode authorize response: %w", err)
	}
	if !record.Authorized {
		return AuthorizeBinding{Authorized: false}, nil
	}
	pemStr, err := EncodeECDSAPublicKeyPEMFromXY(record.Alg, record.X, record.Y)
	if err != nil {
		return AuthorizeBinding{}, fmt.Errorf("authorize key: %w", err)
	}
	return AuthorizeBinding{
		Authorized:      true,
		SigningKey:      LogSigningKey{PublicKeyPEM: pemStr, Alg: strings.TrimSpace(record.Alg)},
		RootLogIDHex:    hex.EncodeToString(record.RootLogID),
		ChainID:         strings.TrimSpace(record.ChainID),
		ContractAddress: strings.TrimSpace(record.Contract),
		Source:          strings.TrimSpace(record.Source),
	}, nil
}
