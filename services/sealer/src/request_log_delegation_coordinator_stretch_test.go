package sealer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// TestRequestLogDelegationLease_BYOKCoordinatorStretch exercises deployed
// coordinator public-root + custodian delegation proxy using production Sealer
// trust-root wiring. Opt-in: E2E_COORDINATOR_SEALER_STRETCH=1 and:
//
//   - TRUST_ROOT_URL, TRUST_ROOT_TOKEN
//   - DELEGATION_ISSUER_URL, DELEGATION_ISSUER_TOKEN
func TestRequestLogDelegationLease_BYOKCoordinatorStretch(t *testing.T) {
	if os.Getenv("E2E_COORDINATOR_SEALER_STRETCH") != "1" {
		t.Skip("set E2E_COORDINATOR_SEALER_STRETCH=1 to run deployed coordinator stretch")
	}
	trustURL := strings.TrimSpace(os.Getenv("TRUST_ROOT_URL"))
	trustToken := strings.TrimSpace(os.Getenv("TRUST_ROOT_TOKEN"))
	issuerURL := strings.TrimSpace(os.Getenv("DELEGATION_ISSUER_URL"))
	issuerToken := strings.TrimSpace(os.Getenv("DELEGATION_ISSUER_TOKEN"))
	if trustURL == "" || trustToken == "" || issuerURL == "" || issuerToken == "" {
		t.Skip("TRUST_ROOT_URL, TRUST_ROOT_TOKEN, DELEGATION_ISSUER_URL, DELEGATION_ISSUER_TOKEN required")
	}

	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logUUID := uuid.New().String()
	logHex32, err := normalizeForestrieHexID32(logUUID)
	if err != nil {
		t.Fatal(err)
	}
	mmrStart := uint64(0)
	mmrEnd := uint64(2048)

	x := make([]byte, 32)
	y := make([]byte, 32)
	rootPriv.PublicKey.X.FillBytes(x)
	rootPriv.PublicKey.Y.FillBytes(y)

	httpClient := NewHTTPClient(nil)
	ctx := context.Background()

	if err := coordinatorPostSigningRoute(ctx, httpClient, trustURL, trustToken, logUUID); err != nil {
		t.Fatal(err)
	}
	if err := coordinatorPostPublicRoot(ctx, httpClient, trustURL, trustToken, logUUID, x, y); err != nil {
		t.Fatal(err)
	}

	delegatedPubCBOR, err := buildTestDelegatedPublicKeyCBOR(delegationcert.Secp256r1)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, issuedAt, expiresAt, err := buildByokDelegationCertificate(
		rootPriv, logHex32, mmrStart, mmrEnd, delegatedPubCBOR,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinatorPostMaterial(ctx, httpClient, trustURL, trustToken, coordinatorMaterialRequest{
		LogID:              logUUID,
		MMRStart:           mmrStart,
		MMREnd:             mmrEnd,
		DelegatedPublicKey: base64.StdEncoding.EncodeToString(delegatedPubCBOR),
		Certificate:        base64.StdEncoding.EncodeToString(certBytes),
		IssuedAt:           issuedAt,
		ExpiresAt:          expiresAt,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		TrustRootURL:          trustURL,
		TrustRootToken:        trustToken,
		DelegationIssuerURL:   issuerURL,
		DelegationIssuerToken: issuerToken,
		CustodianURL:          issuerURL,
	}
	trustRoot := NewSelectingTrustRootClient(cfg, httpClient)
	issuer := &HTTPDelegationIssuer{
		BaseURL:    issuerURL,
		Token:      issuerToken,
		HTTPClient: httpClient,
	}

	lease, err := RequestLogDelegationLease(
		ctx,
		httpClient,
		trustRoot,
		issuer,
		"secp256r1",
		30*time.Minute,
		logHex32,
		mmrStart,
		mmrEnd,
	)
	if err != nil {
		t.Fatalf("expected deployed BYOK lease: %v", err)
	}
	if len(lease.CertBytes) == 0 {
		t.Fatal("expected non-empty lease certificate")
	}
	if !bytes.Equal(lease.CertBytes, certBytes) {
		t.Fatal("lease certificate does not match uploaded BYOK material")
	}
}

type coordinatorMaterialRequest struct {
	LogID              string `json:"logId"`
	MMRStart           uint64 `json:"mmrStart"`
	MMREnd             uint64 `json:"mmrEnd"`
	DelegatedPublicKey string `json:"delegatedPublicKey"`
	Certificate        string `json:"certificate"`
	IssuedAt           uint64 `json:"issuedAt"`
	ExpiresAt          uint64 `json:"expiresAt"`
}

func coordinatorPostSigningRoute(
	ctx context.Context,
	httpClient *HTTPClient,
	baseURL, token, logUUID string,
) error {
	return coordinatorPostJSON(ctx, httpClient, baseURL, token,
		fmt.Sprintf("/api/logs/%s/signing-route", logUUID),
		map[string]string{"mode": "wallet"},
	)
}

func coordinatorPostPublicRoot(
	ctx context.Context,
	httpClient *HTTPClient,
	baseURL, token, logUUID string,
	x, y []byte,
) error {
	return coordinatorPostJSON(ctx, httpClient, baseURL, token,
		fmt.Sprintf("/api/logs/%s/public-root", logUUID),
		map[string]string{
			"alg": "ES256",
			"x":   base64.StdEncoding.EncodeToString(x),
			"y":   base64.StdEncoding.EncodeToString(y),
		},
	)
}

func coordinatorPostMaterial(
	ctx context.Context,
	httpClient *HTTPClient,
	baseURL, token string,
	body coordinatorMaterialRequest,
) error {
	return coordinatorPostJSON(ctx, httpClient, baseURL, token,
		"/api/delegations/material",
		body,
	)
}

func coordinatorPostJSON(
	ctx context.Context,
	httpClient *HTTPClient,
	baseURL, token, path string,
	body any,
) error {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal body: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, base+path, bytes.NewReader(payload),
	)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s: status=%d body=%s", path, resp.StatusCode, respBody)
	}
	return nil
}

func normalizeForestrieHexID32(raw string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return "", fmt.Errorf("forestrie id must be 32 hex digits, got %d", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", err
	}
	return s, nil
}

func buildTestDelegatedPublicKeyCBOR(curve delegationcert.Curve) ([]byte, error) {
	_, pub, err := generateEphemeralKey(curve)
	if err != nil {
		return nil, err
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	delegatedKey, err := delegationcert.NewDelegatedCoseKey(curve, x, y)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(delegatedKey.ToCBORMap())
}

func buildByokDelegationCertificate(
	rootPriv *ecdsa.PrivateKey,
	logHex32 string,
	mmrStart, mmrEnd uint64,
	delegatedPubCBOR []byte,
) (cert []byte, issuedAt, expiresAt uint64, err error) {
	kid, err := kidFromECDSAPublicKey(&rootPriv.PublicKey)
	if err != nil {
		return nil, 0, 0, err
	}
	delegatedKey, curve, err := delegationcert.ParseDelegatedPublicKeyFromCBOR(delegatedPubCBOR)
	if err != nil {
		return nil, 0, 0, err
	}
	issuedAt = uint64(time.Now().Unix())
	expiresAt = issuedAt + 3600
	tbs, err := delegationcert.BuildDelegationToBeSigned(
		curve,
		kid,
		delegationcert.DelegationInput{
			LogID:        logHex32,
			MmrStart:     mmrStart,
			MmrEnd:       mmrEnd,
			DelegatedKey: delegatedKey,
			Constraints:  map[string]any{},
			DelegationID: make([]byte, 16),
			IssuedAt:     issuedAt,
			ExpiresAt:    expiresAt,
		},
	)
	if err != nil {
		return nil, 0, 0, err
	}
	rSig, sSig, err := ecdsa.Sign(rand.Reader, rootPriv, tbs.SigStructureDigest)
	if err != nil {
		return nil, 0, 0, err
	}
	sig := make([]byte, 64)
	rSig.FillBytes(sig[:32])
	sSig.FillBytes(sig[32:])
	cert, err = delegationcert.AssembleDelegationCert(tbs, sig)
	if err != nil {
		return nil, 0, 0, err
	}
	return cert, issuedAt, expiresAt, nil
}
