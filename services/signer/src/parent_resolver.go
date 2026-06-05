package signer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// ParentResolver resolves parent (auth) log id to the KMS key resource name to use for signing.
// For bootstrap root auth log, returns bootstrap key. For other auth logs, uses map or univocity.
type ParentResolver struct {
	BootstrapKeyID string
	ParentKeys     map[string]string // log id hex (0x-prefixed or not) -> KMS key id
	UnivocityURL   string
	RootLogIDHex   string // cached from univocity GET /api/logs/{id}/root
	HTTPClient     *http.Client
}

// NewParentResolver builds a resolver from config. HTTPClient may be nil to use default.
func NewParentResolver(cfg Config) *ParentResolver {
	client := &http.Client{Timeout: 10 * time.Second}
	return &ParentResolver{
		BootstrapKeyID: cfg.BootstrapKeyID,
		ParentKeys:     cfg.ParentKeyMap(),
		UnivocityURL:   strings.TrimRight(strings.TrimSpace(cfg.UnivocityURL), "/"),
		HTTPClient:     client,
	}
}

// ResolveKeyID returns the KMS key resource name for the given parent (auth) log id.
// parentLogIDHex should be 0x-prefixed 32-byte hex. If parent is the root and we have
// bootstrap key, returns bootstrap. Else looks up ParentKeys; if UnivocityURL is set
// and root not yet known, fetches root and retries. Returns error if not found.
func (p *ParentResolver) ResolveKeyID(ctx context.Context, parentLogIDHex string) (string, error) {
	normalized := normalizeLogIDHex(parentLogIDHex)
	if normalized == "" {
		return "", fmt.Errorf("invalid parent_log_id hex")
	}

	// If we have bootstrap and parent is the root, use bootstrap (simple deployment).
	if p.BootstrapKeyID != "" && p.isRoot(ctx, normalized) {
		return p.BootstrapKeyID, nil
	}

	// Explicit map lookup (log id hex -> key id).
	if p.ParentKeys != nil {
		if keyID, ok := p.ParentKeys[normalized]; ok && keyID != "" {
			return keyID, nil
		}
		// Try with 0x prefix if we stored without.
		if keyID, ok := p.ParentKeys["0x"+normalized]; ok && keyID != "" {
			return keyID, nil
		}
	}

	return "", fmt.Errorf("no key configured for parent log %s", normalized)
}

func normalizeLogIDHex(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	if len(s) != 64 {
		return ""
	}
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return ""
	}
	return s
}

func (p *ParentResolver) isRoot(ctx context.Context, logIDHex string) bool {
	if p.UnivocityURL == "" {
		return false
	}
	root := p.fetchRootLogID(ctx, logIDHex)
	if root == "" {
		return false
	}
	p.RootLogIDHex = root
	normalizedRoot := normalizeLogIDHex(root)
	normalizedParent := normalizeLogIDHex(logIDHex)
	return normalizedRoot != "" && normalizedRoot == normalizedParent
}

func (p *ParentResolver) fetchRootLogID(ctx context.Context, parentLogIDHex string) string {
	if p.HTTPClient == nil {
		return ""
	}
	normalized := normalizeLogIDHex(parentLogIDHex)
	if normalized == "" {
		return ""
	}
	url := p.UnivocityURL + "/api/logs/0x" + normalized + "/root"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		slog.Warn("univocity root lookup transient", "parentLogId", "0x"+normalized)
		return ""
	}
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var out struct {
		Exists    bool   `json:"exists"`
		RootLogId string `json:"rootLogId"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil || !out.Exists {
		return ""
	}
	return out.RootLogId
}
