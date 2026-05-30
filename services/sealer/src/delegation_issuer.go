package sealer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/forestrie/arbor/services/pkgs/logredact"
	"github.com/fxamacker/cbor/v2"
)

// IssuerLeaseRequest is input for DelegationIssuer.IssueForLog.
type IssuerLeaseRequest struct {
	LogIDBytes          []byte
	LogIdHex            string
	MMRStart            uint64
	MMREnd              uint64
	Curve               delegationcert.Curve
	Algorithm           string
	DelegatedPublicKey  []byte
	RequestedTTLSeconds uint64
	RequestID           []byte
}

// IssuerLeaseResponse is the untrusted issuer response (verified locally).
type IssuerLeaseResponse struct {
	Certificate []byte
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// DelegationIssuer obtains delegation lease material from an untrusted issuer.
type DelegationIssuer interface {
	IssueForLog(ctx context.Context, req IssuerLeaseRequest) (*IssuerLeaseResponse, error)
}

// HTTPDelegationIssuer calls POST /api/delegations with CBOR request/response.
type HTTPDelegationIssuer struct {
	BaseURL    string
	Token      string
	HTTPClient *HTTPClient
}

func (h *HTTPDelegationIssuer) IssueForLog(
	ctx context.Context,
	req IssuerLeaseRequest,
) (*IssuerLeaseResponse, error) {
	if h == nil || h.HTTPClient == nil {
		return nil, fmt.Errorf("delegation issuer not configured")
	}
	base := strings.TrimRight(strings.TrimSpace(h.BaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("delegation issuer URL is empty")
	}
	if strings.TrimSpace(h.Token) == "" {
		return nil, fmt.Errorf("delegation issuer token is empty")
	}

	logID := req.LogIDBytes
	if len(logID) == 0 && req.LogIdHex != "" {
		// Wire format prefers 16-byte raw log id; fall back to hex decode if needed.
		if b, err := decodeLogIDHex(req.LogIdHex); err == nil {
			logID = b
		}
	}

	issueReq := delegationcert.DelegationIssueRequest{
		Version:             1,
		LogID:               logID,
		MMRStart:            req.MMRStart,
		MMREnd:              req.MMREnd,
		Algorithm:           req.Algorithm,
		DelegatedPublicKey:  req.DelegatedPublicKey,
		RequestedTTLSeconds: req.RequestedTTLSeconds,
		RequestID:           req.RequestID,
	}
	body, err := cbor.Marshal(issueReq)
	if err != nil {
		return nil, fmt.Errorf("encode delegation issue request: %w", err)
	}

	endpoint := base + "/api/delegations"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+h.Token)
	httpReq.Header.Set("Content-Type", "application/cbor")
	httpReq.Header.Set("Accept", "application/cbor")

	resp, err := h.HTTPClient.Do(ctx, httpReq)
	if err != nil {
		return nil, fmt.Errorf("delegation issuer request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, fmt.Errorf("read delegation issuer response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if isDelegationPendingResponse(resp.StatusCode, resp.Header.Get("Content-Type"), respBytes) {
			return nil, ErrDelegationPending
		}
		return nil, fmt.Errorf(
			"delegation issuer returned status=%d: body_sha256=%s",
			resp.StatusCode,
			logredact.SHA256Hex(respBytes),
		)
	}

	var issueResp delegationcert.DelegationIssueResponse
	if err := cbor.Unmarshal(respBytes, &issueResp); err != nil {
		return nil, fmt.Errorf("decode delegation issue response: %w", err)
	}
	if len(issueResp.Certificate) == 0 {
		return nil, fmt.Errorf("delegation issuer returned empty certificate")
	}

	return &IssuerLeaseResponse{
		Certificate: issueResp.Certificate,
		IssuedAt:    time.Unix(issueResp.IssuedAt, 0).UTC(),
		ExpiresAt:   time.Unix(issueResp.ExpiresAt, 0).UTC(),
	}, nil
}

func isDelegationPendingResponse(status int, contentType string, body []byte) bool {
	if status != http.StatusServiceUnavailable {
		return false
	}
	if !strings.Contains(strings.ToLower(contentType), "application/problem+cbor") {
		return false
	}
	var problem map[string]any
	if err := cbor.Unmarshal(body, &problem); err != nil {
		return false
	}
	detail, _ := problem["detail"].(string)
	detail = strings.ToLower(detail)
	return strings.Contains(detail, "delegation material not found") ||
		strings.Contains(detail, "delegation material not available")
}
