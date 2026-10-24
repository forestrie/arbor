package sealer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// pendingIssuerStub records every issuance request and answers each with
// ErrDelegationPending, as the coordinator does while an owner has not signed.
type pendingIssuerStub struct {
	requests []IssuerLeaseRequest
}

func (s *pendingIssuerStub) IssueForLog(_ context.Context, req IssuerLeaseRequest) (*IssuerLeaseResponse, error) {
	s.requests = append(s.requests, req)
	return nil, ErrDelegationPending
}

func TestHTTPDelegationIssuer_MapsMaterialMissing503ToPending(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		title  string
	}{
		{
			name:   "503 legacy",
			status: http.StatusServiceUnavailable,
			title:  "Service Unavailable",
		},
		{
			name:   "202 accepted",
			status: http.StatusAccepted,
			title:  "Accepted",
		},
	} {
		for _, detail := range []string{
			"delegation material not found for requested range and key",
			"delegation material not available",
		} {
			t.Run(tc.name+"/"+detail, func(t *testing.T) {
				body, err := cbor.Marshal(map[string]any{
					"type":   "about:blank",
					"title":  tc.title,
					"status": tc.status,
					"detail": detail,
				})
				if err != nil {
					t.Fatal(err)
				}
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/problem+cbor")
					w.WriteHeader(tc.status)
					_, _ = w.Write(body)
				}))
				defer srv.Close()

				issuer := &HTTPDelegationIssuer{
					BaseURL:    srv.URL,
					Token:      "token",
					HTTPClient: NewHTTPClient(nil),
				}
				_, err = issuer.IssueForLog(context.Background(), IssuerLeaseRequest{
					LogIDBytes:          make([]byte, 16),
					MMRStart:            0,
					MMREnd:              1,
					Algorithm:           "ES256",
					DelegatedPublicKey:  []byte{1, 2, 3},
					RequestedTTLSeconds: 3600,
				})
				if !errors.Is(err, ErrDelegationPending) {
					t.Fatalf("got %v want ErrDelegationPending", err)
				}
			})
		}
	}
}
