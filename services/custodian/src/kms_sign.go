package custodian

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	if ck.Primary != nil && ck.Primary.Name != "" {
		return ck.Primary.Name, ck.Primary.Algorithm, nil
	}
	// Some keys / API responses omit Primary; use highest ENABLED version instead.
	return kmsLatestEnabledSigningVersion(ctx, client, cryptoKeyResource)
}

// kmsLatestEnabledSigningVersion picks the ENABLED CryptoKeyVersion with the
// largest numeric suffix (…/cryptoKeyVersions/N). Requires list on the CryptoKey.
func kmsLatestEnabledSigningVersion(ctx context.Context, client *kms.KeyManagementClient, cryptoKeyName string) (versionName string, versionAlg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, err error) {
	it := client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
		Parent: cryptoKeyName,
	})
	var (
		bestName string
		bestAlg  kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		bestN    int64 = -1
	)
	for {
		ver, e := it.Next()
		if e == iterator.Done {
			break
		}
		if e != nil {
			return "", 0, fmt.Errorf("list crypto key versions: %w", e)
		}
		if ver.State != kmspb.CryptoKeyVersion_ENABLED {
			continue
		}
		n := cryptoKeyVersionNumber(ver.Name)
		if n > bestN {
			bestN = n
			bestName = ver.Name
			bestAlg = ver.Algorithm
		}
	}
	if bestN < 0 {
		return "", 0, fmt.Errorf("crypto key has no enabled version")
	}
	return bestName, bestAlg, nil
}

func cryptoKeyVersionNumber(versionResourceName string) int64 {
	const p = "/cryptoKeyVersions/"
	i := strings.LastIndex(versionResourceName, p)
	if i < 0 {
		return 0
	}
	n, err := strconv.ParseInt(versionResourceName[i+len(p):], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// kmsPublicKeyAlgString maps KMS signing algorithm to Custodian wire alg (ES256, KS256).
func kmsPublicKeyAlgString(a kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (string, error) {
	switch a {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		return "ES256", nil
	case kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256:
		return "KS256", nil
	default:
		return "", fmt.Errorf("unsupported KMS algorithm for public key: %v", a)
	}
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

// kmsPublicKeyPEMAndAlg fetches PEM and Custodian wire alg for a CryptoKey resource name.
func kmsPublicKeyPEMAndAlg(ctx context.Context, cryptoKeyName string) (pem string, alg string, err error) {
	client, err := newKMSClient(ctx)
	if err != nil {
		return "", "", err
	}
	defer client.Close()
	versionName, versionAlg, err := kmsResolveSigningVersion(ctx, client, cryptoKeyName)
	if err != nil {
		return "", "", err
	}
	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
	if err != nil {
		return "", "", err
	}
	algStr, err := kmsPublicKeyAlgString(versionAlg)
	if err != nil {
		return "", "", err
	}
	return pubResp.GetPem(), algStr, nil
}

// kmsErrIsNotFound reports whether err indicates the CryptoKey or version does not exist in KMS.
func kmsErrIsNotFound(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		return true
	}
	var ge *googleapi.Error
	return errors.As(err, &ge) && ge.Code == http.StatusNotFound
}
