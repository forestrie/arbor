package custodian

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// ResolveKeyName returns the full KMS CryptoKey resource name for keyID.
// keyID may be a full name (projects/.../cryptoKeys/...) or a short id (e.g. log-owner-xxx).
func (a *API) ResolveKeyName(keyID string) (string, error) {
	if a.cfg.CustodyKeyRingID == "" {
		return "", fmt.Errorf("CUSTODY_KEY_RING_ID not set")
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return "", fmt.Errorf("key_id required")
	}
	if strings.HasPrefix(keyID, "projects/") && strings.Contains(keyID, "/cryptoKeys/") {
		return keyID, nil
	}
	return a.cfg.CustodyKeyRingID + "/cryptoKeys/" + keyID, nil
}

// DestroyKey schedules destruction of all versions of the given key.
// Each version enters DESTROY_SCHEDULED; key material is destroyed after the key's destroyScheduledDuration.
// Requires cloudkms.admin or cloudkms.cryptoKeyVersions.destroy on the key.
func (a *API) DestroyKey(ctx context.Context, keyName string) (destroyedCount int, err error) {
	client, err := kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return 0, fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()

	it := client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
		Parent: keyName,
	})
	for {
		ver, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return destroyedCount, fmt.Errorf("list versions: %w", err)
		}
		// Only destroy versions that are still usable (ENABLED, etc.); skip already DESTROYED/DESTROY_SCHEDULED
		switch ver.State {
		case kmspb.CryptoKeyVersion_ENABLED, kmspb.CryptoKeyVersion_DISABLED:
			_, err = client.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{Name: ver.Name})
			if err != nil {
				return destroyedCount, fmt.Errorf("destroy %s: %w", ver.Name, err)
			}
			destroyedCount++
		default:
			// PENDING_GENERATION, DESTROY_SCHEDULED, DESTROYED, IMPORT_FAILED, GENERATION_FAILED: skip or already gone
		}
	}
	return destroyedCount, nil
}

// DestroyKeyVersionsFrom schedules destruction of all versions with version number <= maxVersion.
// Version numbers are taken from the last path segment of the version name (e.g. .../cryptoKeyVersions/2 -> 2).
func (a *API) DestroyKeyVersionsFrom(ctx context.Context, keyName string, maxVersion int) (destroyedCount int, err error) {
	client, err := kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return 0, fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()

	it := client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
		Parent: keyName,
	})
	for {
		ver, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return destroyedCount, fmt.Errorf("list versions: %w", err)
		}
		vid, parseErr := versionIDFromName(ver.Name)
		if parseErr != nil || vid > maxVersion {
			continue
		}
		switch ver.State {
		case kmspb.CryptoKeyVersion_ENABLED, kmspb.CryptoKeyVersion_DISABLED:
			_, err = client.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{Name: ver.Name})
			if err != nil {
				return destroyedCount, fmt.Errorf("destroy %s: %w", ver.Name, err)
			}
			destroyedCount++
		default:
			// already scheduled or destroyed
		}
	}
	return destroyedCount, nil
}

func versionIDFromName(name string) (int, error) {
	// .../cryptoKeyVersions/1
	const prefix = "/cryptoKeyVersions/"
	i := strings.LastIndex(name, prefix)
	if i < 0 {
		return 0, fmt.Errorf("invalid version name")
	}
	s := strings.TrimPrefix(name[i:], prefix)
	return strconv.Atoi(s)
}
