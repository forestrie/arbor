package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// univocityAuthorityWire mirrors univocity's GET /api/logs/{logId}/authority
// response (services/univocity handlers.go authorityResponse). Declared
// here so the tests pin the wire contract independently of the decoder.
type univocityAuthorityWire struct {
	LogID      []byte `cbor:"logId,omitempty"`
	RootLogID  []byte `cbor:"rootLogId,omitempty"`
	OwnerLogID []byte `cbor:"ownerLogId,omitempty"`
	State      string `cbor:"state"`
	Alg        int64  `cbor:"alg,omitempty"`
	Key        []byte `cbor:"key,omitempty"`
	ChainID    string `cbor:"chainId,omitempty"`
	Contract   string `cbor:"contract,omitempty"`
	Source     string `cbor:"source,omitempty"`
	ExpiresAt  int64  `cbor:"expiresAt,omitempty"`
	BlockedBy  []byte `cbor:"blockedBy,omitempty"`
	Final      bool   `cbor:"final"`
}

// authorityAnswer is what the fake univocity answers: an HTTP status other
// than 200, or the log's authority state.
type authorityAnswer struct {
	status    int
	state     string
	noKey     bool // a root whose contract is not deployed has no key
	blockedBy []byte
	final     bool
}

// fakeUnivocity is a fake univocity authority endpoint. It answers every log
// with its root key and the current answer, and counts the requests.
type fakeUnivocity struct {
	*httptest.Server
	mu     sync.Mutex
	answer authorityAnswer
	calls  int
}

func (f *fakeUnivocity) set(a authorityAnswer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = a
}

func (f *fakeUnivocity) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// newAuthorityServer stands up a fake univocity that answers pub as an
// anchored log's final root key, or errStatus when it is non-zero.
func newAuthorityServer(t *testing.T, pub *ecdsa.PublicKey, errStatus int) *fakeUnivocity {
	t.Helper()
	key := make([]byte, 64)
	if pub != nil {
		pub.X.FillBytes(key[:32])
		pub.Y.FillBytes(key[32:])
	}
	f := &fakeUnivocity{answer: authorityAnswer{status: errStatus, state: "anchored", final: true}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			!strings.HasPrefix(r.URL.Path, "/api/logs/") ||
			!strings.HasSuffix(r.URL.Path, "/authority") {
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		f.calls++
		a := f.answer
		f.mu.Unlock()
		if a.status != 0 {
			w.WriteHeader(a.status)
			return
		}
		resp := univocityAuthorityWire{
			RootLogID: make([]byte, 16),
			State:     a.state,
			ChainID:   "84532",
			Contract:  "0x000000000000000000000000000000000000abcd",
			Source:    "grant",
			BlockedBy: a.blockedBy,
			Final:     a.final,
		}
		if !a.noKey {
			resp.Alg, resp.Key = coseAlgES256, key
		}
		body, _ := cbor.Marshal(resp)
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(body)
	}))
	return f
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

	lease, err := requestLogDelegationLease(
		context.Background(), NewHTTPClient(nil), resolver, issuer, nil,
		"secp256r1", 30*time.Minute, logID, 7, 21, standingKeys(t),
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

	_, err = requestLogDelegationLease(
		context.Background(), NewHTTPClient(nil),
		&HTTPAuthorityResolver{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)},
		&HTTPDelegationIssuer{BaseURL: issuerSrv.URL, Token: byokIssuerToken, HTTPClient: NewHTTPClient(nil)},
		nil,
		"secp256r1", 30*time.Minute, logID, 7, 21, standingKeys(t),
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

	_, err = requestLogDelegationLease(
		context.Background(), NewHTTPClient(nil),
		&HTTPAuthorityResolver{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)},
		&HTTPDelegationIssuer{BaseURL: issuerSrv.URL, Token: byokIssuerToken, HTTPClient: NewHTTPClient(nil)},
		nil,
		"secp256r1", 30*time.Minute, logID, 7, 21, standingKeys(t),
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
	_, err := requestLogDelegationLease(
		context.Background(), NewHTTPClient(nil),
		&HTTPAuthorityResolver{BaseURL: srv.URL, HTTPClient: NewHTTPClient(nil)},
		&HTTPDelegationIssuer{BaseURL: srv.URL, Token: "x", HTTPClient: NewHTTPClient(nil)},
		nil,
		"secp256r1", 30*time.Minute, "2123456789abcdef0123456789abcdef", 7, 21, standingKeys(t),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsAuthorityNotFound(err) {
		t.Fatalf("404 must stay classified through the lease wrap, got %v", err)
	}
}
