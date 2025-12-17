package sealer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// DelegationLease is a time-limited, root-signed delegation certificate paired
// with the delegated private key generated locally by sealer.
type DelegationLease struct {
	CertBytes []byte
	Info      *DelegationCertificateInfo

	Curve      DelegationCurve
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// COSESigner returns a veraison/go-cose Signer + kid + public key to use with
// go-merklelog RootSigner.
func (d *DelegationLease) COSESigner() (cose.Signer, []byte, *ecdsa.PublicKey, error) {
	if d == nil || d.PrivateKey == nil || d.PublicKey == nil {
		return nil, nil, nil, fmt.Errorf("delegation lease missing key material")
	}
	kid, err := kidFromECDSAPublicKey(d.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	switch d.Curve {
	case DelegationCurveSecp256r1:
		s, err := cose.NewSigner(cose.AlgorithmES256, d.PrivateKey)
		return s, kid, d.PublicKey, err
	case DelegationCurveSecp256k1:
		s, err := NewES256KSigner(d.PrivateKey)
		return s, kid, d.PublicKey, err
	default:
		return nil, nil, nil, fmt.Errorf("unsupported delegation curve %q", d.Curve)
	}
}

// RequestGlobalDelegationLease requests a prefix/no-log delegation certificate
// (empty log, unconstrained mmr range) with a time-based expiry.
//
// This uses the Canopy delegation-signer prefix/no-log request shape:
// - delegated_pubkey, constraints, issued_at, expires_at
// and intentionally omits:
// - log_id, mmr_start, mmr_end, log_id_prefix
func RequestGlobalDelegationLease(
	ctx context.Context,
	httpClient *HTTPClient,
	signerBaseURL string,
	accessToken string,
	curveRaw string,
	ttl time.Duration,
) (*DelegationLease, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("http client is nil")
	}
	if strings.TrimSpace(signerBaseURL) == "" {
		return nil, fmt.Errorf("signer base URL is empty")
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("access token is empty")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("ttl must be > 0")
	}

	curve, err := ParseDelegationCurve(curveRaw)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	issuedAtUnix := uint64(now.Unix())
	expiresAtUnix := uint64(now.Add(ttl).Unix())

	var priv *ecdsa.PrivateKey
	switch curve {
	case DelegationCurveSecp256r1:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate P-256 key: %w", err)
		}
		priv = k
	case DelegationCurveSecp256k1:
		k, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("generate secp256k1 key: %w", err)
		}
		priv = k.ToECDSA()
	default:
		return nil, fmt.Errorf("unsupported curve %q", curve)
	}

	pub := &priv.PublicKey

	// delegated_pubkey is a COSE_Key EC2 map with integer labels.
	crv := int64(8) // secp256k1
	if curve == DelegationCurveSecp256r1 {
		crv = 1
	}

	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)

	coseKey := map[int64]any{
		1:  int64(2), // kty = EC2
		-1: crv,      // crv
		-2: x,        // x
		-3: y,        // y
	}

	reqMap := map[string]any{
		"delegated_pubkey": coseKey,
		"constraints":      map[string]any{},
		"issued_at":        issuedAtUnix,
		"expires_at":       expiresAtUnix,
	}

	body, err := cbor.Marshal(reqMap)
	if err != nil {
		return nil, fmt.Errorf("encode CBOR request: %w", err)
	}

	endpoint := strings.TrimRight(strings.TrimSpace(signerBaseURL), "/") + "/api/delegations"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/cbor")

	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("call delegation signer: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("delegation signer returned status=%d", resp.StatusCode)
	}

	info, err := ParseDelegationCertificate(respBytes)
	if err != nil {
		return nil, err
	}

	// Validate that the returned cert is global (prefix/no-log): no log_id/mmr range.
	if strings.TrimSpace(info.PayloadLogID) != "" || strings.TrimSpace(info.PayloadMmrStart) != "" || strings.TrimSpace(info.PayloadMmrEnd) != "" {
		return nil, fmt.Errorf("unexpected log-scoped delegation returned; expected global delegation")
	}
	if info.PayloadExpiresAtUnix == 0 {
		return nil, fmt.Errorf("delegation certificate missing expires_at")
	}

	issuedAt := time.Unix(int64(info.PayloadIssuedAtUnix), 0).UTC()
	expiresAt := time.Unix(int64(info.PayloadExpiresAtUnix), 0).UTC()

	return &DelegationLease{
		CertBytes:  respBytes,
		Info:       info,
		Curve:      curve,
		PrivateKey: priv,
		PublicKey:  pub,
		IssuedAt:   issuedAt,
		ExpiresAt:  expiresAt,
	}, nil
}


