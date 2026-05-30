package custodian

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/fxamacker/cbor/v2"
)

const coordinatorHTTPTimeout = 30 * time.Second

// coordinatorBaseURL returns trimmed DELEGATION_COORDINATOR_URL or empty.
func (a *API) coordinatorBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(a.cfg.DelegationCoordinatorURL), "/")
}

func (a *API) coordinatorAuthToken() string {
	if t := strings.TrimSpace(a.cfg.DelegationCoordinatorToken); t != "" {
		return t
	}
	return a.cfg.AppToken
}

func (a *API) coordinatorConfigured() bool {
	return a.coordinatorBaseURL() != ""
}

// proxyDelegationIssue forwards CBOR body to coordinator POST /api/delegations.
// inboundAuth is ignored for the outbound coordinator call; coordinator auth uses
// DELEGATION_COORDINATOR_TOKEN (or AppToken fallback) from custodian config.
func (a *API) proxyDelegationIssue(ctx context.Context, body []byte, _ string) (*delegationcert.DelegationIssueResponse, int, error) {
	base := a.coordinatorBaseURL()
	if base == "" {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("delegation coordinator URL not configured")
	}
	url := base + "/api/delegations"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/cbor")
	token := a.coordinatorAuthToken()
	if token == "" {
		return nil, http.StatusUnauthorized, fmt.Errorf("coordinator proxy: no bearer token")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: coordinatorHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	if resp.StatusCode == http.StatusAccepted ||
		resp.StatusCode == http.StatusServiceUnavailable {
		if isCoordinatorDelegationPendingBody(respBody) {
			return nil, resp.StatusCode, fmt.Errorf("delegation material not available")
		}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("coordinator issue: status=%d", resp.StatusCode)
	}

	var out delegationcert.DelegationIssueResponse
	if err := custodianCBORdm.Unmarshal(respBody, &out); err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("decode coordinator response: %w", err)
	}
	return &out, http.StatusOK, nil
}

func bearerFromRequest(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("Authorization"))
}

func isCoordinatorDelegationPendingBody(body []byte) bool {
	var problem map[string]any
	if err := cbor.Unmarshal(body, &problem); err != nil {
		return false
	}
	detail, _ := problem["detail"].(string)
	detail = strings.ToLower(detail)
	return strings.Contains(detail, "delegation material not found") ||
		strings.Contains(detail, "delegation material not available")
}
