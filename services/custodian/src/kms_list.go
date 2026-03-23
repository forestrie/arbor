package custodian

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// buildLabelFilter returns a KMS filter expression for the given labels and predicate.
// Predicate "and" => labels.k1=v1 AND labels.k2=v2; "or" => labels.k1=v1 OR labels.k2=v2.
// Label keys are sanitized for the filter (GCP: lowercase, [a-z0-9_-]).
func buildLabelFilter(labels map[string]string, predicate string) string {
	if len(labels) == 0 {
		return ""
	}
	sanitize := func(s string) string {
		s = strings.ToLower(regexp.MustCompile(`[^a-z0-9_-]`).ReplaceAllString(s, "_"))
		if len(s) > 63 {
			return s[:63]
		}
		return s
	}
	var parts []string
	for k, v := range labels {
		key, val := sanitize(k), sanitize(v)
		if key == "" {
			continue
		}
		// Escape value for filter: use quoted string if contains space or specials
		parts = append(parts, fmt.Sprintf("labels.%s=%s", key, val))
	}
	if len(parts) == 0 {
		return ""
	}
	op := " AND "
	if strings.ToLower(strings.TrimSpace(predicate)) == "or" {
		op = " OR "
	}
	return strings.Join(parts, op)
}

// ListKeysWithLabels lists keys in the custody key ring matching the given labels and predicate.
// Predicate "and" = all labels must match; "or" = any label must match.
// Returns key_id (short name), version (latest version number), and count (total versions); count omitted when 1.
func (a *API) ListKeysWithLabels(ctx context.Context, labels map[string]string, predicate string) ([]KeyListEntry, error) {
	if a.cfg.CustodyKeyRingID == "" {
		return nil, fmt.Errorf("CUSTODY_KEY_RING_ID not set")
	}
	client, err := kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()

	filter := buildLabelFilter(labels, predicate)
	req := &kmspb.ListCryptoKeysRequest{
		Parent: a.cfg.CustodyKeyRingID,
		Filter: filter,
	}
	it := client.ListCryptoKeys(ctx, req)
	var entries []KeyListEntry
	for {
		key, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list keys: %w", err)
		}
		keyID := keyIDFromName(key.Name)
		version, count, err := a.getKeyVersionAndCount(ctx, client, key.Name)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", keyID, err)
		}
		e := KeyListEntry{KeyID: keyID, Version: version}
		if count != 1 {
			e.Count = &count
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func keyIDFromName(name string) string {
	const prefix = "/cryptoKeys/"
	i := strings.LastIndex(name, prefix)
	if i < 0 {
		return name
	}
	return strings.TrimPrefix(name[i:], prefix)
}

// getKeyVersionAndCount returns the latest version number and total version count for the key.
func (a *API) getKeyVersionAndCount(ctx context.Context, client *kms.KeyManagementClient, keyName string) (version int, count int, err error) {
	it := client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
		Parent:  keyName,
		OrderBy: "name desc",
	})
	for {
		ver, nerr := it.Next()
		if nerr == iterator.Done {
			break
		}
		if nerr != nil {
			return 0, 0, nerr
		}
		count++
		if version == 0 {
			version, _ = versionIDFromName(ver.Name)
		}
	}
	return version, count, nil
}
