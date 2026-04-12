package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// RequestLogDelegationLease requests a delegation certificate for a specific log
// by calling Custodian directly (no delegation-signer intermediary).
//
// This generates an ephemeral key pair locally, has Custodian sign a delegation
// certificate for that key using the log's custody key, and returns a lease
// containing the cert and ephemeral private key.
func RequestLogDelegationLease(
	ctx context.Context,
	httpClient *HTTPClient,
	custodianURL string,
	appToken string,
	curveRaw string,
	ttl time.Duration,
	logIdHex string,
	mmrStart, mmrEnd uint64,
) (*DelegationLease, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("http client is nil")
	}
	if strings.TrimSpace(custodianURL) == "" {
		return nil, fmt.Errorf("custodian URL is empty")
	}
	if strings.TrimSpace(appToken) == "" {
		return nil, fmt.Errorf("app token is empty")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("ttl must be > 0")
	}
	if strings.TrimSpace(logIdHex) == "" {
		return nil, fmt.Errorf("log ID is empty")
	}

	curve, err := delegationcert.ParseCurve(curveRaw)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	issuedAtUnix := uint64(now.Unix())
	expiresAtUnix := uint64(now.Add(ttl).Unix())

	// Generate ephemeral key pair
	var priv *ecdsa.PrivateKey
	switch curve {
	case delegationcert.Secp256r1:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate P-256 key: %w", err)
		}
		priv = k
	case delegationcert.Secp256k1:
		k, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("generate secp256k1 key: %w", err)
		}
		priv = k.ToECDSA()
	default:
		return nil, fmt.Errorf("unsupported curve %q", curve)
	}
	pub := &priv.PublicKey

	// Get custody key's public key from Custodian to derive kid
	custodyPEM, custodyAlg, err := GetPublicKeyByLogID(ctx, httpClient, custodianURL, logIdHex)
	if err != nil {
		return nil, fmt.Errorf("get custody public key for log %s: %w", logIdHex, err)
	}

	// Verify algorithm matches curve
	if !algMatchesCurve(custodyAlg, curve) {
		return nil, fmt.Errorf("custody key alg %s doesn't match requested curve %s", custodyAlg, curve)
	}

	// Derive kid from custody public key
	kid, err := KidFromPublicKeyPEM(custodyPEM)
	if err != nil {
		return nil, fmt.Errorf("derive kid from custody key: %w", err)
	}

	// Build delegated key
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)

	delegatedKey, err := delegationcert.NewDelegatedCoseKey(curve, x, y)
	if err != nil {
		return nil, fmt.Errorf("build delegated key: %w", err)
	}

	// Generate delegation ID
	delegationID := make([]byte, 16)
	if _, err := rand.Read(delegationID); err != nil {
		return nil, fmt.Errorf("generate delegation ID: %w", err)
	}

	// Build delegation certificate
	input := delegationcert.DelegationInput{
		LogID:        logIdHex,
		MmrStart:     mmrStart,
		MmrEnd:       mmrEnd,
		DelegatedKey: delegatedKey,
		Constraints:  map[string]any{},
		DelegationID: delegationID,
		IssuedAt:     issuedAtUnix,
		ExpiresAt:    expiresAtUnix,
	}

	tbs, err := delegationcert.BuildDelegationToBeSigned(curve, kid, input)
	if err != nil {
		return nil, fmt.Errorf("build delegation to-be-signed: %w", err)
	}

	// Sign via Custodian
	signature, err := SignDigestByLogID(ctx, httpClient, custodianURL, appToken, logIdHex, tbs.SigStructureDigest)
	if err != nil {
		return nil, fmt.Errorf("sign delegation: %w", err)
	}

	// Assemble final certificate
	certBytes, err := delegationcert.AssembleDelegationCert(tbs, signature)
	if err != nil {
		return nil, fmt.Errorf("assemble delegation cert: %w", err)
	}

	// Parse for validation and info extraction
	info, err := delegationcert.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parse delegation cert: %w", err)
	}

	// Validate the certificate looks correct
	if info.PayloadLogID != logIdHex {
		return nil, fmt.Errorf("delegation cert log_id mismatch: got %s, expected %s", info.PayloadLogID, logIdHex)
	}
	if info.PayloadExpiresAtUnix == 0 {
		return nil, fmt.Errorf("delegation certificate missing expires_at")
	}

	issuedAt := time.Unix(int64(info.PayloadIssuedAtUnix), 0).UTC()
	expiresAt := time.Unix(int64(info.PayloadExpiresAtUnix), 0).UTC()

	return &DelegationLease{
		CertBytes:  certBytes,
		Info:       info,
		Curve:      curve,
		PrivateKey: priv,
		PublicKey:  pub,
		IssuedAt:   issuedAt,
		ExpiresAt:  expiresAt,
	}, nil
}

// algMatchesCurve checks if a Custodian algorithm string matches the curve.
func algMatchesCurve(alg string, curve delegationcert.Curve) bool {
	a := strings.TrimSpace(strings.ToUpper(alg))
	switch curve {
	case delegationcert.Secp256r1:
		return a == "ES256"
	case delegationcert.Secp256k1:
		return a == "KS256" || a == "ES256K"
	default:
		return false
	}
}
