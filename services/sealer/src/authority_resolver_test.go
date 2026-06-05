package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// newAuthorizeServer stands up a fake univocity authorize endpoint that returns
// the supplied public key as the authoritative root key (or 401 when deny).
func newAuthorizeServer(t *testing.T, pub *ecdsa.PublicKey, deny bool) *httptest.Server {
	t.Helper()
	x := make([]byte, 32)
	y := make([]byte, 32)
	if pub != nil {
		pub.X.FillBytes(x)
		pub.Y.FillBytes(y)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/authorize" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if deny {
			body, _ := cbor.Marshal(authorizeResponse{Authorized: false})
			w.Header().Set("Content-Type", "application/cbor")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(body)
			return
		}
		body, _ := cbor.Marshal(authorizeResponse{
			Authorized: true,
			RootLogID:  make([]byte, 32),
			Alg:        "ES256",
			X:          x,
			Y:          y,
			ChainID:    "84532",
			Contract:   "0x000000000000000000000000000000000000abcd",
			Source:     "grant",
		})
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(body)
	}))
}

func TestRequestLogDelegationLease_UnivocityAuthorize(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := "0123456789abcdef0123456789abcdef"

	issuerSrv := newBYOKIssuerServer(t, rootPriv, logID, nil)
	defer issuerSrv.Close()
	authSrv := newAuthorizeServer(t, &rootPriv.PublicKey, false)
	defer authSrv.Close()

	authorizer := &HTTPAuthorizeClient{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)}
	issuer := &HTTPDelegationIssuer{
		BaseURL:    issuerSrv.URL,
		Token:      byokIssuerToken,
		HTTPClient: NewHTTPClient(nil),
	}

	lease, err := requestLogDelegationLeaseWithKeyPair(
		context.Background(), NewHTTPClient(nil), nil, authorizer, issuer,
		"secp256r1", 30*time.Minute, logID, 7, 21, nil,
	)
	if err != nil {
		t.Fatalf("expected authorize lease, got %v", err)
	}
	if lease.ChainID != "84532" || lease.AuthSource != "grant" {
		t.Fatalf("expected chain binding in lease, got %+v", lease)
	}
	if lease.ContractAddress == "" {
		t.Fatal("expected contract binding in lease")
	}
}

func TestRequestLogDelegationLease_UnivocityAuthorizeDenied(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := "1123456789abcdef0123456789abcdef"
	issuerSrv := newBYOKIssuerServer(t, rootPriv, logID, nil)
	defer issuerSrv.Close()
	authSrv := newAuthorizeServer(t, &rootPriv.PublicKey, true)
	defer authSrv.Close()

	_, err = requestLogDelegationLeaseWithKeyPair(
		context.Background(), NewHTTPClient(nil), nil,
		&HTTPAuthorizeClient{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)},
		&HTTPDelegationIssuer{BaseURL: issuerSrv.URL, Token: byokIssuerToken, HTTPClient: NewHTTPClient(nil)},
		"secp256r1", 30*time.Minute, logID, 7, 21, nil,
	)
	if err == nil {
		t.Fatal("expected denied authorization to fail")
	}
}

func TestRequestLogDelegationLease_UnivocityAuthorizeWrongKey(t *testing.T) {
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
	// Authorize returns a key that did NOT sign the certificate.
	authSrv := newAuthorizeServer(t, &wrong.PublicKey, false)
	defer authSrv.Close()

	_, err = requestLogDelegationLeaseWithKeyPair(
		context.Background(), NewHTTPClient(nil), nil,
		&HTTPAuthorizeClient{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)},
		&HTTPDelegationIssuer{BaseURL: issuerSrv.URL, Token: byokIssuerToken, HTTPClient: NewHTTPClient(nil)},
		"secp256r1", 30*time.Minute, logID, 7, 21, nil,
	)
	if err == nil {
		t.Fatal("expected mismatched authorize key to fail local verification")
	}
}
