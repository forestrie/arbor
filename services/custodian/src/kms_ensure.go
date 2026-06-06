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

// EnsureKeyForOwner ensures an asymmetric sign key exists in the custody key ring
// (CryptoKey id = selfLogID), grants IAM on it, and returns the public key PEM.
// keyOwnerID and selfLogID must already be normalized 32-char lowercase hex.
// protectionLevel: "HSM" or "SOFTWARE"; defaults to "SOFTWARE".
func (a *API) EnsureKeyForOwner(ctx context.Context, keyOwnerID, selfLogID, alg, protectionLevel string, labels map[string]string) (keyName, publicKeyPEM string, created bool, err error) {
	if err := validateUserLabelKeysNotOperatorPrefix(labels); err != nil {
		return "", "", false, err
	}
	if a.cfg.CustodyKeyRingID == "" {
		return "", "", false, fmt.Errorf("CUSTODY_KEY_RING_ID not set")
	}
	if a.cfg.CustodySignerSAEmail == "" {
		return "", "", false, fmt.Errorf("CUSTODY_SIGNER_SA_EMAIL not set")
	}
	cryptoKeyID := selfLogID
	if len(cryptoKeyID) != 32 || !validCryptoKeyID(cryptoKeyID) {
		return "", "", false, fmt.Errorf("selfLogId must be 32 lowercase hex digits")
	}

	client, err := kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return "", "", false, fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()

	keyResourceName := fmt.Sprintf("%s/cryptoKeys/%s", a.cfg.CustodyKeyRingID, cryptoKeyID)
	key, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyResourceName})
	if err == nil {
		pem, err := a.ensureKeyIAMAndPublicKey(ctx, client, key.Name)
		if err != nil {
			return key.Name, "", false, err
		}
		return key.Name, pem, false, nil
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.NotFound {
		return "", "", false, fmt.Errorf("get crypto key: %w", err)
	}

	kmsLabels := buildCustodyKeyLabels(keyOwnerID, selfLogID, labels)
	protLevel := kmspb.ProtectionLevel_SOFTWARE
	if strings.ToUpper(protectionLevel) == "HSM" {
		protLevel = kmspb.ProtectionLevel_HSM
	}

	createReq := &kmspb.CreateCryptoKeyRequest{
		Parent:      a.cfg.CustodyKeyRingID,
		CryptoKeyId: cryptoKeyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Labels:  kmsLabels,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: protLevel,
			},
		},
	}
	switch strings.ToUpper(alg) {
	case "KS256", "ES256K":
		createReq.CryptoKey.VersionTemplate.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256
	case "ES256", "":
		createReq.CryptoKey.VersionTemplate.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	default:
		createReq.CryptoKey.VersionTemplate.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	}

	key, err = client.CreateCryptoKey(ctx, createReq)
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.AlreadyExists {
			key, err = client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyResourceName})
			if err != nil {
				return "", "", false, fmt.Errorf("get existing crypto key: %w", err)
			}
			pem, err := a.ensureKeyIAMAndPublicKey(ctx, client, key.Name)
			if err != nil {
				return key.Name, "", false, err
			}
			return key.Name, pem, false, nil
		}
		return "", "", false, fmt.Errorf("create crypto key: %w", err)
	}

	pem, err := a.ensureKeyIAMAndPublicKey(ctx, client, key.Name)
	if err != nil {
		return key.Name, "", true, err
	}
	return key.Name, pem, true, nil
}

func buildCustodyKeyLabels(keyOwnerID, selfLogID string, labels map[string]string) map[string]string {
	labelVal := strings.ToLower(regexp.MustCompile(`[^a-z0-9_-]`).ReplaceAllString(keyOwnerID, "-"))
	if len(labelVal) > 63 {
		labelVal = labelVal[:63]
	}
	if labelVal == "" {
		labelVal = "default"
	}
	kmsLabels := map[string]string{
		ForestrieOwnerIDLabelKey: labelVal,
		ForestrieLogIDLabelKey:   selfLogID,
	}
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
	return kmsLabels
}

func (a *API) ensureKeyIAMAndPublicKey(ctx context.Context, client *kms.KeyManagementClient, keyName string) (string, error) {
	custodyMember := "serviceAccount:" + a.cfg.CustodySignerSAEmail
	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: keyName})
	if err != nil {
		return "", fmt.Errorf("get key iam policy: %w", err)
	}
	if policy.Bindings == nil {
		policy.Bindings = []*iampb.Binding{}
	}

	ensureMemberInRole(policy, "roles/cloudkms.signerVerifier", custodyMember)
	ensureMemberInRole(policy, "roles/cloudkms.publicKeyViewer", custodyMember)
	if rt := strings.TrimSpace(a.cfg.CustodianRuntimeSAEmail); rt != "" {
		rtMember := "serviceAccount:" + rt
		ensureMemberInRole(policy, "roles/cloudkms.signerVerifier", rtMember)
		ensureMemberInRole(policy, "roles/cloudkms.publicKeyViewer", rtMember)
	}

	_, err = client.SetIamPolicy(ctx, &iampb.SetIamPolicyRequest{Resource: keyName, Policy: policy})
	if err != nil {
		return "", fmt.Errorf("set key iam policy: %w", err)
	}

	versionName := keyName + "/cryptoKeyVersions/1"
	publicKeyPEM, err := getPublicKeyPEMWithRetry(ctx, client, versionName)
	if err != nil {
		return "", fmt.Errorf("get public key: %w", err)
	}
	return publicKeyPEM, nil
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
