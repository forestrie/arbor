package sealer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type pendingIssuerStub struct {
	requests [][]byte
}

func (s *pendingIssuerStub) IssueForLog(_ context.Context, req IssuerLeaseRequest) (*IssuerLeaseResponse, error) {
	cp := append([]byte(nil), req.DelegatedPublicKey...)
	s.requests = append(s.requests, cp)
	return nil, ErrDelegationPending
}

func TestDelegationLeaseManager_ReusesPendingEphemeralKey(t *testing.T) {
	logID := "0123456789abcdef0123456789abcdef"
	issuer := &pendingIssuerStub{}
	mgr := NewDelegationLeaseManager(
		&stubTrustRootClient{},
		issuer,
		time.Hour,
		time.Minute,
	)

	for i := 0; i < 2; i++ {
		_, err := mgr.EnsureValidForLog(
			context.Background(),
			NewHTTPClient(nil),
			nil,
			"secp256r1",
			logID,
			0,
			1,
		)
		if !errors.Is(err, ErrDelegationPending) {
			t.Fatalf("attempt %d: got %v want ErrDelegationPending", i, err)
		}
	}

	if len(issuer.requests) != 2 {
		t.Fatalf("issuer calls = %d want 2", len(issuer.requests))
	}
	if string(issuer.requests[0]) != string(issuer.requests[1]) {
		t.Fatal("expected pending retry to reuse delegated public key")
	}
}

func TestDelegationLeaseManager_RefreshesPendingKeyAfterTTL(t *testing.T) {
	logID := "1123456789abcdef0123456789abcdef"
	issuer := &pendingIssuerStub{}
	mgr := NewDelegationLeaseManager(
		&stubTrustRootClient{},
		issuer,
		time.Hour,
		time.Minute,
	)

	_, err := mgr.EnsureValidForLog(
		context.Background(),
		NewHTTPClient(nil),
		nil,
		"secp256r1",
		logID,
		0,
		1,
	)
	if !errors.Is(err, ErrDelegationPending) {
		t.Fatalf("got %v want ErrDelegationPending", err)
	}

	mgr.pendingKeys[logID].createdAt = time.Now().Add(-2 * time.Hour)

	_, err = mgr.EnsureValidForLog(
		context.Background(),
		NewHTTPClient(nil),
		nil,
		"secp256r1",
		logID,
		0,
		1,
	)
	if !errors.Is(err, ErrDelegationPending) {
		t.Fatalf("got %v want ErrDelegationPending", err)
	}

	if len(issuer.requests) != 2 {
		t.Fatalf("issuer calls = %d want 2", len(issuer.requests))
	}
	if string(issuer.requests[0]) == string(issuer.requests[1]) {
		t.Fatal("expected expired pending key to be replaced")
	}
}

func TestHTTPDelegationIssuer_MapsMaterialMissing503ToPending(t *testing.T) {
	for _, detail := range []string{
		"delegation material not found for requested range and key",
		"delegation material not available",
	} {
		t.Run(detail, func(t *testing.T) {
			body, err := cbor.Marshal(map[string]any{
				"type":   "about:blank",
				"title":  "Service Unavailable",
				"status": 503,
				"detail": detail,
			})
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+cbor")
				w.WriteHeader(http.StatusServiceUnavailable)
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
