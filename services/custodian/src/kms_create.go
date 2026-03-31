package custodian

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreateKeyForOwner creates a new asymmetric sign key in the custody key ring
// and grants the custody_signer SA signerVerifier and publicKeyViewer on it.
// Optionally grants publicKeyViewer to CustodianRuntimeSAEmail (ADC identity)
// so GetPublicKey succeeds for the creating process.
// selfLogID must be a valid RFC-4122 UUID string; the CryptoKey id is that UUID
// without hyphens (32 lowercase hex digits).
func (a *API) CreateKeyForOwner(ctx context.Context, keyOwnerID, selfLogID, alg string, labels map[string]string) (keyName, publicKeyPEM string, err error) {
	if a.cfg.CustodyKeyRingID == "" {
		return "", "", fmt.Errorf("CUSTODY_KEY_RING_ID not set")
	}
	if a.cfg.CustodySignerSAEmail == "" {
		return "", "", fmt.Errorf("CUSTODY_SIGNER_SA_EMAIL not set")
	}
	cryptoKeyID, uuidOK := cryptoKeyShortIDFromLogUUID(selfLogID)
	if !uuidOK {
		return "", "", fmt.Errorf("selfLogId must be a valid UUID")
	}

	client, err := kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return "", "", fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()

	// Build labels: canonical owner_id plus optional structured labels (GCP: lowercase, [a-z0-9_-], max 63)
	labelVal := strings.ToLower(regexp.MustCompile(`[^a-z0-9_-]`).ReplaceAllString(keyOwnerID, "-"))
	if len(labelVal) > 63 {
		labelVal = labelVal[:63]
	}
	if labelVal == "" {
		labelVal = "default"
	}
	kmsLabels := map[string]string{"owner_id": labelVal}
	for k, v := range labels {
		sanitizedKey := strings.ToLower(regexp.MustCompile(`[^a-z0-9_-]`).ReplaceAllString(k, "_"))
		if len(sanitizedKey) > 63 {
			sanitizedKey = sanitizedKey[:63]
		}
		if sanitizedKey == "" {
			continue
		}
		sanitizedVal := strings.ToLower(regexp.MustCompile(`[^a-z0-9_-]`).ReplaceAllString(v, "_"))
		if len(sanitizedVal) > 63 {
			sanitizedVal = sanitizedVal[:63]
		}
		kmsLabels[sanitizedKey] = sanitizedVal
	}

	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      a.cfg.CustodyKeyRingID,
		CryptoKeyId: cryptoKeyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Labels:  kmsLabels,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
			},
		},
	}
	switch strings.ToUpper(alg) {
	case "KS256", "ES256K":
		req.CryptoKey.VersionTemplate.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256
	case "ES256", "":
		req.CryptoKey.VersionTemplate.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	default:
		req.CryptoKey.VersionTemplate.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	}

	key, err := client.CreateCryptoKey(ctx, req)
	if err != nil {
		return "", "", fmt.Errorf("create crypto key: %w", err)
	}
	keyName = key.Name

	custodyMember := "serviceAccount:" + a.cfg.CustodySignerSAEmail
	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: keyName})
	if err != nil {
		return keyName, "", fmt.Errorf("get key iam policy: %w", err)
	}
	if policy.Bindings == nil {
		policy.Bindings = []*iampb.Binding{}
	}

	ensureMemberInRole(policy, "roles/cloudkms.signerVerifier", custodyMember)
	ensureMemberInRole(policy, "roles/cloudkms.publicKeyViewer", custodyMember)
	if rt := strings.TrimSpace(a.cfg.CustodianRuntimeSAEmail); rt != "" {
		ensureMemberInRole(policy, "roles/cloudkms.publicKeyViewer", "serviceAccount:"+rt)
	}

	_, err = client.SetIamPolicy(ctx, &iampb.SetIamPolicyRequest{Resource: keyName, Policy: policy})
	if err != nil {
		return keyName, "", fmt.Errorf("set key iam policy: %w", err)
	}

	versionName := keyName + "/cryptoKeyVersions/1"
	publicKeyPEM, err = getPublicKeyPEMWithRetry(ctx, client, versionName)
	if err != nil {
		return keyName, "", fmt.Errorf("get public key: %w", err)
	}
	return keyName, publicKeyPEM, nil
}

func ensureMemberInRole(policy *iampb.Policy, role, member string) {
	contains := func(members []string, m string) bool {
		for _, x := range members {
			if x == m {
				return true
			}
		}
		return false
	}
	for _, b := range policy.Bindings {
		if b.Role == role {
			if !contains(b.Members, member) {
				b.Members = append(b.Members, member)
			}
			return
		}
	}
	policy.Bindings = append(policy.Bindings, &iampb.Binding{
		Role:    role,
		Members: []string{member},
	})
}

func getPublicKeyPEMWithRetry(ctx context.Context, client *kms.KeyManagementClient, versionName string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
		if err == nil {
			return pubResp.GetPem(), nil
		}
		lastErr = err
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.PermissionDenied {
			return "", err
		}
		// IAM on new keys can lag slightly after SetIamPolicy.
		time.Sleep(time.Duration(50*(1<<attempt)) * time.Millisecond)
	}
	return "", lastErr
}
