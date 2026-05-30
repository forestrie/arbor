package custodian

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

const coordinatorHTTPTimeout = 30 * time.Second

type coordinatorSigningRoute struct {
	Mode          string `json:"mode"`
	InheritsFrom  string `json:"inheritsFrom,omitempty"`
	ExternalSignerURL string `json:"externalSignerUrl,omitempty"`
}

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

// fetchCoordinatorSigningRouteMode returns mode when route exists, "" if 404, error on failure.
func (a *API) fetchCoordinatorSigningRouteMode(ctx context.Context, logIdHex string) (string, error) {
	base := a.coordinatorBaseURL()
	if base == "" {
		return "", nil
	}
	url := fmt.Sprintf("%s/api/logs/%s/signing-route", base, logIdHex)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	token := a.coordinatorAuthToken()
	if token == "" {
		return "", fmt.Errorf("coordinator auth token not configured")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: coordinatorHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("coordinator signing-route: status=%d body=%s", resp.StatusCode, string(body))
	}

	var route coordinatorSigningRoute
	if err := json.NewDecoder(resp.Body).Decode(&route); err != nil {
		return "", fmt.Errorf("decode coordinator signing-route: %w", err)
	}
	return strings.TrimSpace(route.Mode), nil
}

func (a *API) isWalletManagedLog(ctx context.Context, logIdHex string) bool {
	mode, err := a.fetchCoordinatorSigningRouteMode(ctx, logIdHex)
	if err != nil {
		a.Logger.Warn("coordinator signing-route lookup failed", "log_id", logIdHex, "error", err)
		return false
	}
	return mode == "wallet"
}

// proxyDelegationIssue forwards CBOR body to coordinator POST /api/delegations.
func (a *API) proxyDelegationIssue(ctx context.Context, body []byte, inboundAuth string) (*delegationcert.DelegationIssueResponse, int, error) {
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
	token := strings.TrimSpace(inboundAuth)
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	if token == "" {
		token = a.coordinatorAuthToken()
	}
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

	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("delegation material not available")
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
