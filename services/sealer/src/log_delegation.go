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
	return requestLogDelegationLeaseWithKeyPair(
		ctx, httpClient, trustRoot, nil, issuer, curveRaw, ttl,
		logIdHex, mmrStart, mmrEnd, nil,
	)
}

// DelegatedKeyPair is the private/public checkpoint keypair submitted for
// issuer authorization. BYOK pending retries reuse this process-local keypair
// until a lease is issued or the pending cache expires.
type DelegatedKeyPair struct {
	Private *ecdsa.PrivateKey
	Public  *ecdsa.PublicKey
}

func requestLogDelegationLeaseWithKeyPair(
	ctx context.Context,
	httpClient *HTTPClient,
	trustRoot TrustRootClient,
	resolver AuthorityResolver,
	issuer DelegationIssuer,
	curveRaw string,
	ttl time.Duration,
	logIdHex string,
	mmrStart, mmrEnd uint64,
	keyPair *DelegatedKeyPair,
) (*DelegationLease, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("http client is nil")
	}
	if resolver == nil && trustRoot == nil {
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

	if keyPair == nil {
		priv, pub, err := generateEphemeralKey(curve)
		if err != nil {
			return nil, err
		}
		keyPair = &DelegatedKeyPair{Private: priv, Public: pub}
	}
	if keyPair.Private == nil || keyPair.Public == nil {
		return nil, fmt.Errorf("delegated keypair is incomplete")
	}

	x := make([]byte, 32)
	y := make([]byte, 32)
	keyPair.Public.X.FillBytes(x)
	keyPair.Public.Y.FillBytes(y)
	delegatedKey, err := delegationcert.NewDelegatedCoseKey(curve, x, y)
	if err != nil {
		return nil, fmt.Errorf("build delegated key: %w", err)
	}
	delegatedPubCBOR, err := marshalDelegatedPublicKeyCBOR(delegatedKey)
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

	// Resolve the authoritative root key by logId. The univocity authority
	// resolver also returns the chain binding and resolves cold logs from the
	// grant chain; the legacy trust-root client only resolves logs already on
	// chain. Either way the certificate is verified locally below.
	var rootKey LogSigningKey
	var binding AuthorityBinding
	if resolver != nil {
		binding, err = resolver.ResolveAuthority(ctx, logIdHex)
		if err != nil {
			return nil, fmt.Errorf("resolve authority: %w", err)
		}
		rootKey = binding.SigningKey
	} else {
		rootKey, err = trustRoot.LogSigningKey(ctx, logIdHex)
		if err != nil {
			return nil, fmt.Errorf("trust root: %w", err)
		}
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

	info, err := VerifyDelegationLease(rootKey, issuerResp, LeaseVerificationInput{
		LogIdHex:            logIdHex,
		MMRStart:            mmrStart,
		MMREnd:              mmrEnd,
		Curve:               curve,
		DelegatedPublicKey:  keyPair.Public,
		RequestedTTLSeconds: uint64(ttl.Seconds()),
	})
	if err != nil {
		return nil, fmt.Errorf("verify delegation lease: %w", err)
	}

	return &DelegationLease{
		CertBytes:       issuerResp.Certificate,
		Info:            info,
		Curve:           curve,
		PrivateKey:      keyPair.Private,
		PublicKey:       keyPair.Public,
		IssuedAt:        issuerResp.IssuedAt,
		ExpiresAt:       issuerResp.ExpiresAt,
		RootLogIDHex:    binding.RootLogIDHex,
		ChainID:         binding.ChainID,
		ContractAddress: binding.ContractAddress,
		AuthSource:      binding.Source,
	}, nil
}

func marshalDelegatedPublicKeyCBOR(key *delegationcert.DelegatedCoseKey) ([]byte, error) {
	encMode, err := cbor.EncOptions{Sort: cbor.SortCanonical}.EncMode()
	if err != nil {
		return nil, fmt.Errorf("create delegated key cbor mode: %w", err)
	}
	return encMode.Marshal(key.ToCBORMap())
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
