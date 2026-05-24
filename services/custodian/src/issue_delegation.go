package custodian

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// issueDelegationForLog signs a delegation certificate using a local custody key.
func (a *API) issueDelegationForLog(
	ctx context.Context,
	req *delegationcert.DelegationIssueRequest,
) (*delegationcert.DelegationIssueResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}
	logIdHex, err := logIDHexFromWire(req.LogID)
	if err != nil {
		return nil, err
	}

	keyID, err := a.ResolveCustodianKeyIDForLogID(ctx, logIdHex)
	if err != nil {
		return nil, err
	}

	delegatedKey, curve, err := delegationcert.ParseDelegatedPublicKeyFromCBOR(req.DelegatedPublicKey)
	if err != nil {
		return nil, err
	}
	if req.Algorithm != "" {
		reqCurve, err := delegationcert.CurveFromAlgorithm(req.Algorithm)
		if err != nil {
			return nil, err
		}
		if reqCurve != curve {
			return nil, fmt.Errorf("algorithm %q does not match delegated key curve", req.Algorithm)
		}
	}

	cryptoKeyName, err := a.ResolveKeyName(keyID)
	if err != nil {
		return nil, fmt.Errorf("resolve custody key: %w", err)
	}

	pemStr, alg, err := kmsPublicKeyPEMAndAlg(ctx, cryptoKeyName)
	if err != nil {
		return nil, fmt.Errorf("kms public key: %w", err)
	}
	if !algMatchesDelegationCurve(alg, curve) {
		return nil, fmt.Errorf("custody key alg %s does not match delegated curve %s", alg, curve)
	}

	trustRoot, err := parseECDSAPublicKeyPEM(pemStr)
	if err != nil {
		return nil, err
	}
	kid, err := KidFromECDSAPublicKey(trustRoot)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	issuedAt, expiresAt := leaseTimestampsFromRequest(req, now)
	delegationID, err := delegationIDFromRequest(req.RequestID)
	if err != nil {
		return nil, err
	}

	input := delegationcert.DelegationInput{
		LogID:        logIdHex,
		MmrStart:     req.MMRStart,
		MmrEnd:       req.MMREnd,
		DelegatedKey: delegatedKey,
		Constraints:  map[string]any{},
		DelegationID: delegationID,
		IssuedAt:     issuedAt,
		ExpiresAt:    expiresAt,
	}

	tbs, err := delegationcert.BuildDelegationToBeSigned(curve, kid, input)
	if err != nil {
		return nil, fmt.Errorf("build delegation tbs: %w", err)
	}

	client, err := newKMSClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()

	versionName, _, err := kmsResolveSigningVersion(ctx, client, cryptoKeyName)
	if err != nil {
		return nil, fmt.Errorf("kms resolve signing version: %w", err)
	}

	der, err := kmsAsymmetricSignSHA256(ctx, client, versionName, tbs.SigStructureDigest)
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}
	rawSig, err := ecdsaDERSignatureToIEEE1363(der, 32)
	if err != nil {
		return nil, fmt.Errorf("der to ieee p1363: %w", err)
	}

	certBytes, err := delegationcert.AssembleDelegationCert(tbs, rawSig)
	if err != nil {
		return nil, fmt.Errorf("assemble delegation cert: %w", err)
	}

	return &delegationcert.DelegationIssueResponse{
		Version:     1,
		IssuedAt:    int64(issuedAt),
		ExpiresAt:   int64(expiresAt),
		Certificate: certBytes,
	}, nil
}

func parseECDSAPublicKeyPEM(pemStr string) (*ecdsa.PublicKey, error) {
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

func delegationIssueHTTPStatus(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, ErrNoCustodianKeyForLogID) {
		return 404
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "logid") ||
		strings.Contains(msg, "delegated public key") ||
		strings.Contains(msg, "algorithm") ||
		strings.Contains(msg, "does not match") {
		return 400
	}
	return 500
}
