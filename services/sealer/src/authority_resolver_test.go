package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// newAuthorityServer stands up a fake univocity authority endpoint that returns
// the supplied public key as the authoritative root key (or 503 when notFound).
func newAuthorityServer(t *testing.T, pub *ecdsa.PublicKey, errStatus int) *httptest.Server {
	t.Helper()
	x := make([]byte, 32)
	y := make([]byte, 32)
	if pub != nil {
		pub.X.FillBytes(x)
		pub.Y.FillBytes(y)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			!strings.HasPrefix(r.URL.Path, "/api/logs/") ||
			!strings.HasSuffix(r.URL.Path, "/authority") {
			http.NotFound(w, r)
			return
		}
		if errStatus != 0 {
			w.WriteHeader(errStatus)
			return
		}
		key := make([]byte, 64)
		copy(key[:32], x)
		copy(key[32:], y)
		body, _ := cbor.Marshal(authorityResponse{
			RootLogID: make([]byte, 32),
			Alg:       coseAlgES256,
			Key:       key,
			ChainID:   "84532",
			Contract:  "0x000000000000000000000000000000000000abcd",
			Source:    "grant",
		})
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(body)
	}))
}

func TestRequestLogDelegationLease_UnivocityAuthority(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := "0123456789abcdef0123456789abcdef"

	issuerSrv := newBYOKIssuerServer(t, rootPriv, logID, nil)
	defer issuerSrv.Close()
	authSrv := newAuthorityServer(t, &rootPriv.PublicKey, 0)
	defer authSrv.Close()

	resolver := &HTTPAuthorityResolver{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)}
	issuer := &HTTPDelegationIssuer{
		BaseURL:    issuerSrv.URL,
		Token:      byokIssuerToken,
		HTTPClient: NewHTTPClient(nil),
	}

	lease, err := requestLogDelegationLeaseWithKeyPair(
		context.Background(), NewHTTPClient(nil), nil, resolver, issuer, nil,
		"secp256r1", 30*time.Minute, logID, 7, 21, nil, nil,
	)
	if err != nil {
		t.Fatalf("expected authority lease, got %v", err)
	}
	if lease.ChainID != "84532" || lease.AuthSource != "grant" {
		t.Fatalf("expected chain binding in lease, got %+v", lease)
	}
	if lease.ContractAddress == "" {
		t.Fatal("expected contract binding in lease")
	}
}

func TestRequestLogDelegationLease_UnivocityAuthorityUnresolved(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := "1123456789abcdef0123456789abcdef"
	issuerSrv := newBYOKIssuerServer(t, rootPriv, logID, nil)
	defer issuerSrv.Close()
	authSrv := newAuthorityServer(t, &rootPriv.PublicKey, http.StatusServiceUnavailable)
	defer authSrv.Close()

	_, err = requestLogDelegationLeaseWithKeyPair(
		context.Background(), NewHTTPClient(nil), nil,
		&HTTPAuthorityResolver{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)},
		&HTTPDelegationIssuer{BaseURL: issuerSrv.URL, Token: byokIssuerToken, HTTPClient: NewHTTPClient(nil)},
		nil,
		"secp256r1", 30*time.Minute, logID, 7, 21, nil, nil,
	)
	if err == nil {
		t.Fatal("expected unresolved authority to fail")
	}
}

func TestRequestLogDelegationLease_UnivocityAuthorityWrongKey(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := "2123456789abcdef0123456789abcdef"
	issuerSrv := newBYOKIssuerServer(t, rootPriv, logID, nil)
	defer issuerSrv.Close()
	// Authority returns a key that did NOT sign the certificate.
	authSrv := newAuthorityServer(t, &wrong.PublicKey, 0)
	defer authSrv.Close()

	_, err = requestLogDelegationLeaseWithKeyPair(
		context.Background(), NewHTTPClient(nil), nil,
		&HTTPAuthorityResolver{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)},
		&HTTPDelegationIssuer{BaseURL: issuerSrv.URL, Token: byokIssuerToken, HTTPClient: NewHTTPClient(nil)},
		nil,
		"secp256r1", 30*time.Minute, logID, 7, 21, nil, nil,
	)
	if err == nil {
		t.Fatal("expected mismatched authority key to fail local verification")
	}
}

// TestResolveAuthority_StatusClassification pins the plan-2607-10 slice 04
// contract: 404 (log unknown — permanent until repaired) is distinguishable
// from transient statuses via IsAuthorityNotFound.
func TestResolveAuthority_StatusClassification(t *testing.T) {
	cases := []struct {
		status   int
		notFound bool
	}{
		{http.StatusNotFound, true},
		{http.StatusServiceUnavailable, false},
		{http.StatusBadGateway, false},
	}
	for _, tc := range cases {
		srv := newAuthorityServer(t, nil, tc.status)
		resolver := &HTTPAuthorityResolver{BaseURL: srv.URL, HTTPClient: NewHTTPClient(nil)}
		_, err := resolver.ResolveAuthority(context.Background(), "0123456789abcdef0123456789abcdef")
		srv.Close()
		if err == nil {
			t.Fatalf("status %d: expected error", tc.status)
		}
		if got := IsAuthorityNotFound(err); got != tc.notFound {
			t.Fatalf("status %d: IsAuthorityNotFound=%v want %v (err=%v)", tc.status, got, tc.notFound, err)
		}
	}
}

// The lease path must preserve the classification through its error wrap so
// callers never re-enter a transient retry for a 404.
func TestRequestLogDelegationLease_AuthorityNotFoundClassified(t *testing.T) {
	srv := newAuthorityServer(t, nil, http.StatusNotFound)
	defer srv.Close()
	_, err := requestLogDelegationLeaseWithKeyPair(
		context.Background(), NewHTTPClient(nil), nil,
		&HTTPAuthorityResolver{BaseURL: srv.URL, HTTPClient: NewHTTPClient(nil)},
		&HTTPDelegationIssuer{BaseURL: srv.URL, Token: "x", HTTPClient: NewHTTPClient(nil)},
		nil,
		"secp256r1", 30*time.Minute, "2123456789abcdef0123456789abcdef", 7, 21, nil, nil,
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsAuthorityNotFound(err) {
		t.Fatalf("404 must stay classified through the lease wrap, got %v", err)
	}
}
