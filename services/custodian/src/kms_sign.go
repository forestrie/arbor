package custodian

import (
	"context"
	"fmt"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
)

// kmsResolveSigningVersion returns the CryptoKeyVersion name and algorithm for signing.
// If cryptoKeyResource names a version, that version is used; otherwise the key's primary.
func kmsResolveSigningVersion(ctx context.Context, client *kms.KeyManagementClient, cryptoKeyResource string) (versionName string, versionAlg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, err error) {
	if strings.Contains(cryptoKeyResource, "/cryptoKeyVersions/") {
		ver, e := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: cryptoKeyResource})
		if e != nil {
			return "", 0, fmt.Errorf("get crypto key version: %w", e)
		}
		return ver.Name, ver.Algorithm, nil
	}
	ck, e := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: cryptoKeyResource})
	if e != nil {
		return "", 0, fmt.Errorf("get crypto key: %w", e)
	}
	if ck.Primary == nil || ck.Primary.Name == "" {
		return "", 0, fmt.Errorf("crypto key has no primary version")
	}
	return ck.Primary.Name, ck.Primary.Algorithm, nil
}

// kmsAsymmetricSignSHA256 calls Cloud KMS asymmetricSign with a SHA-256 digest,
// equivalent to canopy kmsAsymmetricSignSha256 (REST body digest.sha256).
func kmsAsymmetricSignSHA256(ctx context.Context, client *kms.KeyManagementClient, cryptoKeyVersionName string, digestSha256 []byte) ([]byte, error) {
	if len(digestSha256) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digestSha256))
	}
	resp, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:   cryptoKeyVersionName,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digestSha256}},
	})
	if err != nil {
		return nil, fmt.Errorf("kms asymmetric sign: %w", err)
	}
	if resp.Signature == nil {
		return nil, fmt.Errorf("kms returned nil signature")
	}
	return resp.Signature, nil
}

func newKMSClient(ctx context.Context) (*kms.KeyManagementClient, error) {
	return kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
}
