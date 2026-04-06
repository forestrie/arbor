package custodian

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrNoCustodianKeyForLogID means KMS list returned no custody key for the log label.
var ErrNoCustodianKeyForLogID = errors.New("no key for log_id")

// ErrAmbiguousCustodianLogID means more than one custody key matched the log label.
var ErrAmbiguousCustodianLogID = errors.New("ambiguous log_id")

// NormalizeLogIDForKMSLabel normalizes a log identifier for use as a KMS label value
// and for comparison with ROOT_LOG_ID (32 lowercase hex digits; hyphens and 0x stripped).
func NormalizeLogIDForKMSLabel(raw string) (string, error) {
	s, err := NormalizeForestrieHexID32(raw)
	if err != nil {
		return "", fmt.Errorf("log_id required")
	}
	return s, nil
}

// ResolveCustodianKeyIDForLogID maps a log id to a Custodian route key id (short custody id or :bootstrap).
func (a *API) ResolveCustodianKeyIDForLogID(ctx context.Context, rawLogID string) (string, error) {
	norm, err := NormalizeLogIDForKMSLabel(rawLogID)
	if err != nil {
		return "", err
	}
	if a.logIDKeyCache != nil {
		if kid, hit := a.logIDKeyCache.Get(norm); hit {
			return kid, nil
		}
	}
	labels := map[string]string{ForestrieLogIDLabelKey: norm}
	entries, err := a.ListKeysWithLabels(ctx, labels, "and")
	if err != nil {
		return "", err
	}
	return resolveCustodianKeyFromEntries(norm, entries, a.cfg.RootLogID, a.logIDKeyCache)
}

// resolveCustodianKeyFromEntries maps KMS list results (+ optional root log id) to a route key id.
// Returns ErrNoCustodianKeyForLogID when no custody key matches and log id is not the configured root.
func resolveCustodianKeyFromEntries(norm string, entries []KeyListEntry, rootLogID string, cache *logIDKeyLRU) (string, error) {
	switch len(entries) {
	case 0:
		root := strings.TrimSpace(strings.ToLower(strings.TrimPrefix(rootLogID, "0x")))
		root = strings.ReplaceAll(root, "-", "")
		if root != "" && norm == root {
			if cache != nil {
				cache.Put(norm, BootstrapKeyAlias)
			}
			return BootstrapKeyAlias, nil
		}
		return "", ErrNoCustodianKeyForLogID
	case 1:
		kid := entries[0].KeyID
		if cache != nil {
			cache.Put(norm, kid)
		}
		return kid, nil
	default:
		return "", fmt.Errorf("%w: %d keys", ErrAmbiguousCustodianLogID, len(entries))
	}
}

func queryLogIDTreatAsLogID(r *http.Request) bool {
	if r == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("log-id")))
	return v == "true" || v == "1"
}

func (a *API) resolveKeyPathSegment(r *http.Request, pathKeyID string) (string, error) {
	if !queryLogIDTreatAsLogID(r) {
		return pathKeyID, nil
	}
	pathKeyID = strings.TrimSpace(pathKeyID)
	if pathKeyID == "" {
		return "", fmt.Errorf("key segment required")
	}
	// Explicit bootstrap alias: never treat as log-id hex.
	if pathKeyID == BootstrapKeyAlias {
		return BootstrapKeyAlias, nil
	}
	return a.ResolveCustodianKeyIDForLogID(r.Context(), pathKeyID)
}
