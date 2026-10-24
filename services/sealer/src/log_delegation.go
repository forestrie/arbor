package sealer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/fxamacker/cbor/v2"
)

// requestLogDelegationLease obtains a verified delegation lease for the
// current standing key in heldKeys over [mmrStart, mmrEnd], via the issuer
// and trust root (or authority resolver) seams. The returned certificate may
// be bound to any held key (rotation overlap); the lease signs with that one.
func requestLogDelegationLease(
	ctx context.Context,
	httpClient *HTTPClient,
	trustRoot TrustRootClient,
	resolver AuthorityResolver,
	issuer DelegationIssuer,
	erc1271 delegationcert.ERC1271Verifier,
	curveRaw string,
	ttl time.Duration,
	logIdHex string,
	mmrStart, mmrEnd uint64,
	heldKeys *DelegateKeySet,
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
	if heldKeys == nil || heldKeys.Current() == nil {
		return nil, ErrNoStandingDelegateKeys
	}

	curve, err := delegationcert.ParseCurve(curveRaw)
	if err != nil {
		return nil, err
	}

	if curve != delegationcert.Secp256r1 {
		return nil, fmt.Errorf("unsupported curve %q (only secp256r1)", curve)
	}
	requested := &heldKeys.Current().PublicKey

	x := make([]byte, 32)
	y := make([]byte, 32)
	requested.X.FillBytes(x)
	requested.Y.FillBytes(y)
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

	// Resolve the authoritative root key by logId.
	// resolver also returns the chain binding and resolves cold logs from the
	// grant chain; the legacy trust-root client only resolves logs already on
	// chain. Either way the certificate is verified locally below.
	var rootKey LogSigningKey
	var binding AuthorityBinding
	if resolver != nil {
		binding, err = resolver.ResolveAuthority(ctx, logIdHex)
		if err != nil {
			// 404 = the log has no locator at univocity; re-attempting
			// cannot succeed until the mapping is repaired (idempotent
			// grant re-post or rootLogId hint) — do not treat as transient
			// (plan-2607-10 slice 04).
			if IsAuthorityNotFound(err) {
				slog.Warn("log authority unknown to univocity; permanent until repaired",
					"logId", logIdHex,
					"remedy", "idempotent grant re-post or rootLogId hint")
			}
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
		HeldPublicKeyHashes: heldKeys.HeldPubkeyHashes(),
	})
	if err != nil {
		return nil, fmt.Errorf("delegation issuer: %w", err)
	}

	info, err := VerifyDelegationLease(rootKey, issuerResp, LeaseVerificationInput{
		LogIdHex:            logIdHex,
		MMRStart:            mmrStart,
		MMREnd:              mmrEnd,
		Curve:               curve,
		RequestedTTLSeconds: uint64(ttl.Seconds()),
		HeldKeys:            heldKeys,
	}, erc1271)
	if err != nil {
		return nil, fmt.Errorf("verify delegation lease: %w", err)
	}

	// Signing key resolution (B4): the returned certificate may be bound to a
	// standing key other than the one requested (rotation overlap), so resolve
	// the private key from the certificate's own bound key rather than
	// assuming the requested one.
	delegated, _, err := delegationcert.DelegatedKeyFromCertificate(issuerResp.Certificate)
	if err != nil {
		return nil, fmt.Errorf("read cert delegated key: %w", err)
	}
	certPub, err := ecdsaFromDelegatedCoseKey(delegated)
	if err != nil {
		return nil, fmt.Errorf("decode cert delegated key: %w", err)
	}
	signingPriv := heldKeys.KeyFor(certPub)
	if signingPriv == nil {
		return nil, fmt.Errorf("no held delegate key for the issued certificate")
	}

	return &DelegationLease{
		CertBytes:       issuerResp.Certificate,
		OnchainProof:    issuerResp.OnchainProof,
		Info:            info,
		Curve:           curve,
		PrivateKey:      signingPriv,
		PublicKey:       &signingPriv.PublicKey,
		IssuedAt:        issuerResp.IssuedAt,
		ExpiresAt:       issuerResp.ExpiresAt,
		RootLogIDHex:    binding.RootLogIDHex,
		ChainID:         binding.ChainID,
		ContractAddress: binding.ContractAddress,
		AuthSource:      binding.Source,
	}, nil
}

func marshalDelegatedPublicKeyCBOR(key *delegationcert.DelegatedCoseKey) ([]byte, error) {
	// RFC 8949 §4.2 core deterministic (bytewise), consistent with
	// delegationcert and the TS @canopy/encoding writer. See build_certificate.go.
	encMode, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	if err != nil {
		return nil, fmt.Errorf("create delegated key cbor mode: %w", err)
	}
	return encMode.Marshal(key.ToCBORMap())
}

// algMatchesCurve checks if a trust-root algorithm string matches the delegated curve.
func algMatchesCurve(alg string, curve delegationcert.Curve) bool {
	a := strings.TrimSpace(strings.ToUpper(alg))
	return curve == delegationcert.Secp256r1 && a == "ES256"
}
