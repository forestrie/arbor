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
	"github.com/fxamacker/cbor/v2"
)

// RequestLogDelegationLease obtains a verified delegation lease via issuer + trust root seams.
func RequestLogDelegationLease(
	ctx context.Context,
	httpClient *HTTPClient,
	trustRoot TrustRootClient,
	issuer DelegationIssuer,
	curveRaw string,
	ttl time.Duration,
	logIdHex string,
	mmrStart, mmrEnd uint64,
) (*DelegationLease, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("http client is nil")
	}
	if trustRoot == nil {
		return nil, fmt.Errorf("trust root client is nil")
	}
	if issuer == nil {
		return nil, fmt.Errorf("delegation issuer is nil")
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

	priv, pub, err := generateEphemeralKey(curve)
	if err != nil {
		return nil, err
	}

	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	delegatedKey, err := delegationcert.NewDelegatedCoseKey(curve, x, y)
	if err != nil {
		return nil, fmt.Errorf("build delegated key: %w", err)
	}
	delegatedPubCBOR, err := cbor.Marshal(delegatedKey.ToCBORMap())
	if err != nil {
		return nil, fmt.Errorf("encode delegated public key: %w", err)
	}

	logIDBytes, err := decodeLogIDHex(logIdHex)
	if err != nil {
		return nil, err
	}

	algorithm := "ES256"
	if curve == delegationcert.Secp256k1 {
		algorithm = "KS256"
	}

	issuerResp, err := issuer.IssueForLog(ctx, IssuerLeaseRequest{
		LogIDBytes:          logIDBytes,
		LogIdHex:            logIdHex,
		MMRStart:            mmrStart,
		MMREnd:              mmrEnd,
		Curve:               curve,
		Algorithm:           algorithm,
		DelegatedPublicKey:  delegatedPubCBOR,
		RequestedTTLSeconds: uint64(ttl.Seconds()),
	})
	if err != nil {
		return nil, fmt.Errorf("delegation issuer: %w", err)
	}

	rootKey, err := trustRoot.LogSigningKey(ctx, logIdHex)
	if err != nil {
		return nil, fmt.Errorf("trust root: %w", err)
	}

	info, err := VerifyDelegationLease(rootKey, issuerResp, LeaseVerificationInput{
		LogIdHex:            logIdHex,
		MMRStart:            mmrStart,
		MMREnd:              mmrEnd,
		Curve:               curve,
		DelegatedPublicKey:  pub,
		RequestedTTLSeconds: uint64(ttl.Seconds()),
	})
	if err != nil {
		return nil, fmt.Errorf("verify delegation lease: %w", err)
	}

	return &DelegationLease{
		CertBytes:  issuerResp.Certificate,
		Info:       info,
		Curve:      curve,
		PrivateKey: priv,
		PublicKey:  pub,
		IssuedAt:   issuerResp.IssuedAt,
		ExpiresAt:  issuerResp.ExpiresAt,
	}, nil
}

func generateEphemeralKey(curve delegationcert.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	switch curve {
	case delegationcert.Secp256r1:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate P-256 key: %w", err)
		}
		return k, &k.PublicKey, nil
	case delegationcert.Secp256k1:
		k, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return nil, nil, fmt.Errorf("generate secp256k1 key: %w", err)
		}
		priv := k.ToECDSA()
		return priv, &priv.PublicKey, nil
	default:
		return nil, nil, fmt.Errorf("unsupported curve %q", curve)
	}
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
