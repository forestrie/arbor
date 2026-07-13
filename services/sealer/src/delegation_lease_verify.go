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

	// CoverageOK relaxes the range check from exact-match to coverage
	// (cert range must contain [MMRStart, MMREnd]) for delegation-in-advance:
	// the coordinator returns a wide standing certificate for a narrow seal
	// window (FOR-390 phase D / B5). The on-chain range check is itself
	// coverage, so a wider cert verifies the narrow seal correctly.
	CoverageOK bool

	// HeldKeys, when set, accepts a certificate bound to ANY standing delegate
	// key the sealer holds (not just DelegatedPublicKey) — rotation overlap
	// means a still-valid cert may be bound to the epoch N-1 key while the
	// request advertised epoch N. Key resolution then picks the matching
	// private key (FOR-390 phase D / B4).
	HeldKeys *DelegateKeySet
}

// VerifyDelegationLease checks issuer material against the trust root and request.
func VerifyDelegationLease(
	trustRoot LogSigningKey,
	issuerResp *IssuerLeaseResponse,
	req LeaseVerificationInput,
	erc1271 delegationcert.ERC1271Verifier,
) (*delegationcert.CertificateInfo, error) {
	if issuerResp == nil || len(issuerResp.Certificate) == 0 {
		return nil, fmt.Errorf("issuer response missing certificate")
	}

	if trustRoot.IsKS256Root() {
		if req.Curve != delegationcert.Secp256r1 {
			return nil, fmt.Errorf("KS256 root may only delegate to an ES256 key")
		}
		if len(trustRoot.KS256Signer) != 20 {
			return nil, fmt.Errorf("KS256 trust root missing 20-byte signer address")
		}
		if err := delegationcert.VerifyCertificateSignatureKS256(
			issuerResp.Certificate,
			trustRoot.KS256Signer,
			erc1271,
		); err != nil {
			return nil, err
		}
	} else {
		if strings.TrimSpace(trustRoot.PublicKeyPEM) == "" {
			return nil, fmt.Errorf("trust root public key is empty")
		}
		if !algMatchesCurve(trustRoot.Alg, req.Curve) {
			return nil, fmt.Errorf(
				"trust root alg %s does not match curve %s",
				trustRoot.Alg, req.Curve,
			)
		}
		trustPub, err := ParseECDSAPublicKeyFromPEM(trustRoot.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse trust root public key: %w", err)
		}
		if err := delegationcert.VerifyCertificateSignature(
			issuerResp.Certificate, trustPub, req.Curve,
		); err != nil {
			return nil, err
		}
	}

	info, err := delegationcert.ParseCertificate(issuerResp.Certificate)
	if err != nil {
		return nil, err
	}
	if info.PayloadLogID != req.LogIdHex {
		return nil, fmt.Errorf(
			"delegation cert log_id mismatch: got %s, expected %s",
			info.PayloadLogID, req.LogIdHex,
		)
	}
	if req.CoverageOK {
		start, errStart := parseUint64Decimal(info.PayloadMmrStart)
		end, errEnd := parseUint64Decimal(info.PayloadMmrEnd)
		if errStart != nil || errEnd != nil {
			return nil, fmt.Errorf("delegation cert has non-decimal mmr bounds")
		}
		if !(start <= req.MMRStart && end >= req.MMREnd) {
			return nil, fmt.Errorf(
				"delegation cert range [%d,%d] does not cover seal window [%d,%d]",
				start, end, req.MMRStart, req.MMREnd,
			)
		}
	} else {
		if info.PayloadMmrStart != fmt.Sprintf("%d", req.MMRStart) {
			return nil, fmt.Errorf("delegation cert mmr_start mismatch")
		}
		if info.PayloadMmrEnd != fmt.Sprintf("%d", req.MMREnd) {
			return nil, fmt.Errorf("delegation cert mmr_end mismatch")
		}
	}
	if info.PayloadExpiresAtUnix == 0 {
		return nil, fmt.Errorf("delegation certificate missing expires_at")
	}

	delegated, _, err := delegationcert.DelegatedKeyFromCertificate(issuerResp.Certificate)
	if err != nil {
		return nil, err
	}
	if req.HeldKeys != nil {
		pub, err := ecdsaFromDelegatedCoseKey(delegated)
		if err != nil {
			return nil, fmt.Errorf("decode cert delegated key: %w", err)
		}
		if req.HeldKeys.KeyFor(pub) == nil {
			return nil, fmt.Errorf("delegation cert is not bound to a held delegate key")
		}
	} else if !delegationcert.DelegatedKeyMatches(delegated, req.DelegatedPublicKey) {
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
