package sealer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// CustodianPublicKeyResponse holds the response from GET /api/keys/{keyId}/public.
type CustodianPublicKeyResponse struct {
	PublicKey string `cbor:"publicKey"` // PEM-encoded SPKI
	Alg       string `cbor:"alg"`       // "ES256" or "KS256"
}

// CustodianSignRequest is the CBOR request body for POST /api/keys/{keyId}/sign.
type CustodianSignRequest struct {
	PayloadHash      []byte `cbor:"payloadHash"`      // SHA-256 digest (32 bytes)
	RawSignatureOnly bool   `cbor:"rawSignatureOnly"` // true to get IEEE P1363 signature
}

// CustodianSignResponse is the CBOR response from sign with rawSignatureOnly.
type CustodianSignResponse struct {
	Signature []byte `cbor:"signature"` // 64-byte IEEE P1363 r||s
}

// GetPublicKeyByLogID fetches the public key for a log ID from Custodian.
// Uses GET /api/keys/{logIdHex}/public?log-id=true to resolve the custody key.
//
// Returns the PEM-encoded public key and algorithm ("ES256" or "KS256").
func GetPublicKeyByLogID(
	ctx context.Context,
	httpClient *HTTPClient,
	custodianURL string,
	logIdHex string,
) (publicKeyPEM string, alg string, err error) {
	base := strings.TrimRight(strings.TrimSpace(custodianURL), "/")
	if base == "" {
		return "", "", fmt.Errorf("custodian URL is empty")
	}

	// URL-encode the log ID and add ?log-id=true
	endpoint := fmt.Sprintf("%s/api/keys/%s/public?log-id=true", base, url.PathEscape(logIdHex))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/cbor")

	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		return "", "", fmt.Errorf("custodian request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("custodian returned status=%d for log %s", resp.StatusCode, logIdHex)
	}

	var result CustodianPublicKeyResponse
	if err := cbor.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("decode CBOR response: %w", err)
	}

	if result.PublicKey == "" {
		return "", "", fmt.Errorf("custodian returned empty public key")
	}

	return result.PublicKey, result.Alg, nil
}

// SignDigestByLogID signs a SHA-256 digest using the custody key for a log ID.
// Uses POST /api/keys/{logIdHex}/sign?log-id=true with rawSignatureOnly=true.
//
// Returns the 64-byte IEEE P1363 signature (r||s).
func SignDigestByLogID(
	ctx context.Context,
	httpClient *HTTPClient,
	custodianURL string,
	appToken string,
	logIdHex string,
	digest []byte,
) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes")
	}

	base := strings.TrimRight(strings.TrimSpace(custodianURL), "/")
	if base == "" {
		return nil, fmt.Errorf("custodian URL is empty")
	}
	if strings.TrimSpace(appToken) == "" {
		return nil, fmt.Errorf("app token is empty")
	}

	endpoint := fmt.Sprintf("%s/api/keys/%s/sign?log-id=true", base, url.PathEscape(logIdHex))

	reqBody := CustodianSignRequest{
		PayloadHash:      digest,
		RawSignatureOnly: true,
	}
	bodyBytes, err := canonicalCBOR.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+appToken)
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("Accept", "application/cbor")

	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("custodian request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("custodian sign returned status=%d for log %s", resp.StatusCode, logIdHex)
	}

	var result CustodianSignResponse
	if err := cbor.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode CBOR response: %w", err)
	}

	if len(result.Signature) != 64 {
		return nil, fmt.Errorf("expected 64-byte signature, got %d bytes", len(result.Signature))
	}

	return result.Signature, nil
}

// ParseECDSAPublicKeyFromPEM parses a PEM-encoded SPKI public key.
func ParseECDSAPublicKeyFromPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in public key")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}
	return pub, nil
}

// KidFromPublicKeyPEM derives a 16-byte key identifier from a PEM-encoded public key.
// The kid is the first 16 bytes of SHA-256(uncompressed point).
func KidFromPublicKeyPEM(pemStr string) ([]byte, error) {
	pub, err := ParseECDSAPublicKeyFromPEM(pemStr)
	if err != nil {
		return nil, err
	}
	// kidFromECDSAPublicKey is defined in sealer.go
	return kidFromECDSAPublicKey(pub)
}
