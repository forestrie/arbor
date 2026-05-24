package sealer

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// LeaseVerificationInput captures the sealer-side delegation request context.
type LeaseVerificationInput struct {
	LogIdHex            string
	MMRStart            uint64
	MMREnd              uint64
	Curve               delegationcert.Curve
	DelegatedPublicKey  *ecdsa.PublicKey
	RequestedTTLSeconds uint64
}

// VerifyDelegationLease checks issuer material against the trust root and request.
func VerifyDelegationLease(
	trustRoot LogSigningKey,
	issuerResp *IssuerLeaseResponse,
	req LeaseVerificationInput,
) (*delegationcert.CertificateInfo, error) {
	if issuerResp == nil || len(issuerResp.Certificate) == 0 {
		return nil, fmt.Errorf("issuer response missing certificate")
	}
	if strings.TrimSpace(trustRoot.PublicKeyPEM) == "" {
		return nil, fmt.Errorf("trust root public key is empty")
	}
	if !algMatchesCurve(trustRoot.Alg, req.Curve) {
		return nil, fmt.Errorf("trust root alg %s does not match curve %s", trustRoot.Alg, req.Curve)
	}

	trustPub, err := ParseECDSAPublicKeyFromPEM(trustRoot.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse trust root public key: %w", err)
	}
	if err := delegationcert.VerifyCertificateSignature(issuerResp.Certificate, trustPub, req.Curve); err != nil {
		return nil, err
	}

	info, err := delegationcert.ParseCertificate(issuerResp.Certificate)
	if err != nil {
		return nil, err
	}
	if info.PayloadLogID != req.LogIdHex {
		return nil, fmt.Errorf("delegation cert log_id mismatch: got %s, expected %s", info.PayloadLogID, req.LogIdHex)
	}
	if info.PayloadMmrStart != fmt.Sprintf("%d", req.MMRStart) {
		return nil, fmt.Errorf("delegation cert mmr_start mismatch")
	}
	if info.PayloadMmrEnd != fmt.Sprintf("%d", req.MMREnd) {
		return nil, fmt.Errorf("delegation cert mmr_end mismatch")
	}
	if info.PayloadExpiresAtUnix == 0 {
		return nil, fmt.Errorf("delegation certificate missing expires_at")
	}

	delegated, _, err := delegationcert.DelegatedKeyFromCertificate(issuerResp.Certificate)
	if err != nil {
		return nil, err
	}
	if !delegationcert.DelegatedKeyMatches(delegated, req.DelegatedPublicKey) {
		return nil, fmt.Errorf("delegated public key does not match ephemeral key")
	}

	now := time.Now().UTC()
	if !now.Before(issuerResp.ExpiresAt) {
		return nil, fmt.Errorf("delegation lease already expired")
	}
	if req.RequestedTTLSeconds > 0 {
		minExpires := now.Add(time.Duration(req.RequestedTTLSeconds) * time.Second)
		if issuerResp.ExpiresAt.Before(minExpires.Add(-2 * time.Minute)) {
			return nil, fmt.Errorf("delegation lease expires too soon for requested ttl")
		}
	}

	return info, nil
}

func decodeLogIDHex(logIdHex string) ([]byte, error) {
	s := strings.TrimSpace(strings.ToLower(logIdHex))
	if len(s) != 32 {
		return nil, fmt.Errorf("log id hex must be 32 characters")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("log id must decode to 16 bytes")
	}
	return b, nil
}
