package custodian

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/veraison/go-cose"
)

// Forestrie custodian Sign1 profile: COSE payload is the 32-byte SHA-256 digest (bstr)
// being attested; protected includes alg, cty, kid per forest-1 COSE arc.
const custodianStatementCTY = "application/forestrie.custodian-statement+cbor"

func coseAlgFromKMS(a kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (cose.Algorithm, error) {
	switch a {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		return cose.AlgorithmES256, nil
	case kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256:
		return cose.Algorithm(-47), nil
	default:
		return 0, fmt.Errorf("unsupported KMS signing algorithm %v", a)
	}
}

func parseECDSAPublicKeyFromPEM(pemStr string) (*ecdsa.PublicKey, error) {
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

// BuildCustodianCOSESign1 returns an untagged COSE_Sign1 CBOR value (four-element array).
func BuildCustodianCOSESign1(
	ctx context.Context,
	client *kms.KeyManagementClient,
	versionName string,
	versionAlg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm,
	payloadDigest []byte,
) ([]byte, error) {
	if len(payloadDigest) != 32 {
		return nil, fmt.Errorf("payload digest must be 32 bytes")
	}
	alg, err := coseAlgFromKMS(versionAlg)
	if err != nil {
		return nil, err
	}
	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}
	pub, err := parseECDSAPublicKeyFromPEM(pubResp.GetPem())
	if err != nil {
		return nil, err
	}
	kid, err := KidFromECDSAPublicKey(pub)
	if err != nil {
		return nil, err
	}

	msg := cose.NewSign1Message()
	msg.Headers.Protected = cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm:   alg,
		cose.HeaderLabelContentType: custodianStatementCTY,
		cose.HeaderLabelKeyID:       kid,
	}
	msg.Payload = payloadDigest

	// Cloud KMS returns ECDSA signatures as ASN.1 DER; COSE / go-cose expect IEEE P1363 R‖S.
	const coordWidth = 32
	signer := &kmsCOSESigner{
		alg: alg,
		ctx: ctx,
		sign: func(c context.Context, digest []byte) ([]byte, error) {
			der, err := kmsAsymmetricSignSHA256(c, client, versionName, digest)
			if err != nil {
				return nil, err
			}
			return ecdsaDERSignatureToIEEE1363(der, coordWidth)
		},
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("cose sign1: %w", err)
	}

	u := cose.UntaggedSign1Message(*msg)
	return u.MarshalCBOR()
}
