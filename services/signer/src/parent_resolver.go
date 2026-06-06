package signer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/logid"
)

// ParentResolver resolves parent (auth) log id to the KMS key resource name to use for signing.
// For bootstrap root auth log, returns bootstrap key. For other auth logs, uses map or univocity.
type ParentResolver struct {
	BootstrapKeyID string
	ParentKeys     map[string]string // canonical UUID -> KMS key id
	UnivocityURL   string
	RootLogID      logid.UUID // cached forest root R (from univocity)
	HTTPClient     *http.Client
}

// NewParentResolver builds a resolver from config. HTTPClient may be nil to use default.
func NewParentResolver(cfg Config) *ParentResolver {
	client := &http.Client{Timeout: 10 * time.Second}
	return &ParentResolver{
		BootstrapKeyID: cfg.BootstrapKeyID,
		ParentKeys:     normalizeParentKeyMap(cfg.ParentKeyMap()),
		UnivocityURL:   strings.TrimRight(strings.TrimSpace(cfg.UnivocityURL), "/"),
		HTTPClient:     client,
	}
}

// ResolveKeyID returns the KMS key resource name for the given parent (auth) log id.
// parentLogID must be a canonical dashed UUID on the HTTP API (not bytes32 chain hex).
func (p *ParentResolver) ResolveKeyID(ctx context.Context, parentLogID string) (string, error) {
	parentUUID, err := parseParentLogID(parentLogID)
	if err != nil {
		return "", err
	}

	// If we have bootstrap and parent is the root, use bootstrap (simple deployment).
	if p.BootstrapKeyID != "" && p.isRoot(ctx, parentUUID) {
		return p.BootstrapKeyID, nil
	}

	// Explicit map lookup (canonical UUID -> key id).
	if p.ParentKeys != nil {
		if keyID, ok := p.ParentKeys[parentUUID.String()]; ok && keyID != "" {
			return keyID, nil
		}
	}

	return "", fmt.Errorf("no key configured for parent log %s", parentUUID.String())
}

func parseParentLogID(s string) (logid.UUID, error) {
	u, err := logid.ParseCanonicalSegment(s)
	if err != nil {
		return logid.Zero, fmt.Errorf("invalid parent_log_id: %w", err)
	}
	return u, nil
}

// normalizeParentKeyMap converts config keys (canonical UUID or custodian 32-hex) to
// canonical dashed UUID strings. Chain bytes32 (64-hex) is not accepted.
func normalizeParentKeyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		u, err := logid.ParseSegment(strings.TrimSpace(k))
		if err != nil {
			continue
		}
		out[u.String()] = v
	}
	return out
}

func (p *ParentResolver) isRoot(ctx context.Context, parentUUID logid.UUID) bool {
	if p.UnivocityURL == "" {
		return false
	}
	root := p.fetchRootLogID(ctx, parentUUID)
	if root.IsZero() {
		return false
	}
	p.RootLogID = root
	return root == parentUUID
}

func (p *ParentResolver) fetchRootLogID(ctx context.Context, parentUUID logid.UUID) logid.UUID {
	if p.HTTPClient == nil {
		return logid.Zero
	}
	url := p.UnivocityURL + "/api/logs/" + parentUUID.String() + "/root"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return logid.Zero
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return logid.Zero
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		slog.Warn("univocity root lookup transient", "parentLogId", parentUUID.String())
		return logid.Zero
	}
	if resp.StatusCode != http.StatusOK {
		return logid.Zero
	}
	var out struct {
		Exists    bool   `json:"exists"`
		RootLogId string `json:"rootLogId"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil || !out.Exists {
		return logid.Zero
	}
	root, err := logid.ParseUUIDString(out.RootLogId)
	if err != nil {
		return logid.Zero
	}
	return root
}
