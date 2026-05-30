package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// HTTPTrustRootClient resolves trust roots from a generic HTTP trust-root
// service. The wire format is the plan-0003 CBOR shape returned by
// GET {BaseURL}/api/logs/{logIdHex}/signing-key.
//
// The client treats the upstream as an untrusted read proxy of contract
// state: it never talks to contracts directly. Production wiring will point
// BaseURL at services/univocity once that service exposes a non-mock
// signing-key endpoint; tests inject an httptest.Server URL.
type HTTPTrustRootClient struct {
	BaseURL    string
	HTTPClient *HTTPClient
}

// LogSigningKey fetches the trust root for a log and converts the CBOR
// (alg, x, y) into the existing LogSigningKey PEM shape so the lease verify
// path needs no changes.
func (c *HTTPTrustRootClient) LogSigningKey(
	ctx context.Context,
	logIdHex string,
) (LogSigningKey, error) {
	if c == nil || c.HTTPClient == nil {
		return LogSigningKey{}, fmt.Errorf("http trust root client not configured")
	}
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		return LogSigningKey{}, fmt.Errorf("http trust root base URL is empty")
	}
	logID := strings.ToLower(strings.TrimSpace(logIdHex))
	if logID == "" {
		return LogSigningKey{}, fmt.Errorf("log id is empty")
	}

	endpoint := fmt.Sprintf("%s/api/logs/%s/signing-key", base, url.PathEscape(logID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return LogSigningKey{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/cbor")

	resp, err := c.HTTPClient.Do(ctx, req)
	if err != nil {
		return LogSigningKey{}, fmt.Errorf("trust root request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return LogSigningKey{}, fmt.Errorf("read trust root response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return LogSigningKey{}, fmt.Errorf(
			"trust root returned status=%d for log %s",
			resp.StatusCode, logID,
		)
	}
	if len(body) == 0 {
		return LogSigningKey{}, fmt.Errorf("trust root returned empty body")
	}

	var record TrustRootResponse
	if err := cbor.Unmarshal(body, &record); err != nil {
		return LogSigningKey{}, fmt.Errorf("decode trust root CBOR: %w", err)
	}

	pemStr, err := EncodeECDSAPublicKeyPEMFromXY(record.Alg, record.X, record.Y)
	if err != nil {
		return LogSigningKey{}, err
	}

	return LogSigningKey{
		PublicKeyPEM:    pemStr,
		Alg:             strings.TrimSpace(record.Alg),
		Domain:          strings.TrimSpace(record.Domain),
		ChainID:         strings.TrimSpace(record.ChainID),
		ContractAddress: strings.TrimSpace(record.ContractAddress),
	}, nil
}

// EncodeECDSAPublicKeyPEMFromXY builds a PEM-encoded SPKI public key from the
// CBOR-shaped (alg, x, y) trust-root material.
//
// Only ES256 (P-256) is supported in this step. KS256 / secp256k1 will be
// added when the Univocity adapter requires it.
func EncodeECDSAPublicKeyPEMFromXY(alg string, x, y []byte) (string, error) {
	a := strings.ToUpper(strings.TrimSpace(alg))
	var curve elliptic.Curve
	var coordLen int
	switch a {
	case "ES256":
		curve = elliptic.P256()
		coordLen = 32
	default:
		return "", fmt.Errorf("unsupported trust root alg %q", alg)
	}
	if len(x) == 0 || len(y) == 0 {
		return "", fmt.Errorf("trust root public key x/y are empty")
	}
	if len(x) > coordLen || len(y) > coordLen {
		return "", fmt.Errorf(
			"trust root public key coordinates too large for %s (x=%d y=%d)",
			a, len(x), len(y),
		)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	if !curve.IsOnCurve(pub.X, pub.Y) {
		return "", fmt.Errorf("trust root public key is not on curve %s", a)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal trust root public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
