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
func newAuthorityServer(t *testing.T, pub *ecdsa.PublicKey, notFound bool) *httptest.Server {
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
		if notFound {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body, _ := cbor.Marshal(authorityResponse{
			RootLogID: make([]byte, 32),
			Alg:       "ES256",
			X:         x,
			Y:         y,
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
	authSrv := newAuthorityServer(t, &rootPriv.PublicKey, false)
	defer authSrv.Close()

	resolver := &HTTPAuthorityResolver{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)}
	issuer := &HTTPDelegationIssuer{
		BaseURL:    issuerSrv.URL,
		Token:      byokIssuerToken,
		HTTPClient: NewHTTPClient(nil),
	}

	lease, err := requestLogDelegationLeaseWithKeyPair(
		context.Background(), NewHTTPClient(nil), nil, resolver, issuer,
		"secp256r1", 30*time.Minute, logID, 7, 21, nil,
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
	authSrv := newAuthorityServer(t, &rootPriv.PublicKey, true)
	defer authSrv.Close()

	_, err = requestLogDelegationLeaseWithKeyPair(
		context.Background(), NewHTTPClient(nil), nil,
		&HTTPAuthorityResolver{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)},
		&HTTPDelegationIssuer{BaseURL: issuerSrv.URL, Token: byokIssuerToken, HTTPClient: NewHTTPClient(nil)},
		"secp256r1", 30*time.Minute, logID, 7, 21, nil,
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
	authSrv := newAuthorityServer(t, &wrong.PublicKey, false)
	defer authSrv.Close()

	_, err = requestLogDelegationLeaseWithKeyPair(
		context.Background(), NewHTTPClient(nil), nil,
		&HTTPAuthorityResolver{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)},
		&HTTPDelegationIssuer{BaseURL: issuerSrv.URL, Token: byokIssuerToken, HTTPClient: NewHTTPClient(nil)},
		"secp256r1", 30*time.Minute, logID, 7, 21, nil,
	)
	if err == nil {
		t.Fatal("expected mismatched authority key to fail local verification")
	}
}
