package custodian

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	"google.golang.org/api/option"
)

// CreateKeyForOwner creates a new asymmetric sign key in the custody key ring
// and grants the custody_signer SA signerVerifier and publicKeyViewer on it.
// keyOwnerID is used to derive a key name; alg is "ES256" or "KS256".
// labels are optional KMS labels (merged with owner_id); keys/values must be lowercase, [a-z0-9_-], max 63 chars.
func (a *API) CreateKeyForOwner(ctx context.Context, keyOwnerID, alg string, labels map[string]string) (keyName, publicKeyPEM string, err error) {
	if a.cfg.CustodyKeyRingID == "" {
		return "", "", fmt.Errorf("CUSTODY_KEY_RING_ID not set")
	}
	if a.cfg.CustodySignerSAEmail == "" {
		return "", "", fmt.Errorf("CUSTODY_SIGNER_SA_EMAIL not set")
	}
	safe := regexp.MustCompile(`[^a-zA-Z0-9-]`).ReplaceAllString(keyOwnerID, "-")
	if len(safe) > 30 {
		safe = safe[:30]
	}
	if safe == "" {
		safe = "key"
	}
	cryptoKeyID := "log-owner-" + safe

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

	member := "serviceAccount:" + a.cfg.CustodySignerSAEmail
	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: keyName})
	if err != nil {
		return keyName, "", fmt.Errorf("get key iam policy: %w", err)
	}
	if policy.Bindings == nil {
		policy.Bindings = []*iampb.Binding{}
	}
	contains := func(members []string, m string) bool {
		for _, x := range members {
			if x == m {
				return true
			}
		}
		return false
	}
	var hasSigner, hasViewer bool
	for _, b := range policy.Bindings {
		if b.Role == "roles/cloudkms.signerVerifier" {
			hasSigner = true
			if !contains(b.Members, member) {
				b.Members = append(b.Members, member)
			}
		}
		if b.Role == "roles/cloudkms.publicKeyViewer" {
			hasViewer = true
			if !contains(b.Members, member) {
				b.Members = append(b.Members, member)
			}
		}
	}
	if !hasSigner {
		policy.Bindings = append(policy.Bindings, &iampb.Binding{
			Role:    "roles/cloudkms.signerVerifier",
			Members: []string{member},
		})
	}
	if !hasViewer {
		policy.Bindings = append(policy.Bindings, &iampb.Binding{
			Role:    "roles/cloudkms.publicKeyViewer",
			Members: []string{member},
		})
	}
	_, err = client.SetIamPolicy(ctx, &iampb.SetIamPolicyRequest{Resource: keyName, Policy: policy})
	if err != nil {
		return keyName, "", fmt.Errorf("set key iam policy: %w", err)
	}

	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: keyName + "/cryptoKeyVersions/1",
	})
	if err != nil {
		return keyName, "", fmt.Errorf("get public key: %w", err)
	}
	publicKeyPEM = pubResp.GetPem()
	return keyName, publicKeyPEM, nil
}
