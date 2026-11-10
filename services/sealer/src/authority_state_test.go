package sealer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"
)

// Univocity is the only source of root keys, and a log's key is used only
// once univocity reports the log anchored (devdocs ADR-0075 decision 5,
// protocol ADR-0070). These tests drive the lease manager against a fake
// univocity and a fake delegation issuer.

// recordingTransport records every request made through it.
type recordingTransport struct {
	inner http.RoundTripper
	mu    sync.Mutex
	seen  []string
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.seen = append(rt.seen, r.Method+" "+r.URL.Host+r.URL.Path)
	rt.mu.Unlock()
	return rt.inner.RoundTrip(r)
}

// take returns the requests recorded since the last take.
func (rt *recordingTransport) take() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	seen := rt.seen
	rt.seen = nil
	return seen
}

// recordingHTTPClient is an HTTPClient whose every request is recorded.
func recordingHTTPClient() (*HTTPClient, *recordingTransport) {
	hc := NewHTTPClient(nil)
	rt := &recordingTransport{inner: hc.client.Transport}
	hc.client.Transport = rt
	return hc, rt
}

// authorityLeaseFixture is a lease manager wired to a fake univocity and a
// fake issuer that signs with the root key univocity reports.
type authorityLeaseFixture struct {
	t        *testing.T
	univ     *fakeUnivocity
	issuer   string // host
	mgr      *DelegationLeaseManager
	http     *HTTPClient
	recorded *recordingTransport
}

func newAuthorityLeaseFixture(t *testing.T, logIDs ...string) *authorityLeaseFixture {
	t.Helper()
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	univ := newAuthorityServer(t, &rootPriv.PublicKey, 0)
	t.Cleanup(univ.Close)
	// The issuer signs certificates for the first log; tests that lease
	// other logs only reach univocity.
	issuerSrv := newBYOKIssuerServer(t, rootPriv, logIDs[0], nil)
	t.Cleanup(issuerSrv.Close)

	hc, rec := recordingHTTPClient()
	mgr := NewDelegationLeaseManager(
		&HTTPAuthorityResolver{BaseURL: univ.URL, HTTPClient: hc},
		&HTTPDelegationIssuer{BaseURL: issuerSrv.URL, Token: byokIssuerToken, HTTPClient: hc},
		time.Hour, time.Minute,
	)
	mgr.SetDelegateKeys(standingKeys(t))
	return &authorityLeaseFixture{
		t: t, univ: univ, issuer: hostOf(t, issuerSrv.URL), mgr: mgr, http: hc, recorded: rec,
	}
}

func (f *authorityLeaseFixture) lease(logID string) (*DelegationLease, error) {
	return f.mgr.EnsureValidForLog(f.t.Context(), f.http, nil, "secp256r1", logID, 7, 21)
}

func (f *authorityLeaseFixture) authorityRequest(logID string) string {
	f.t.Helper()
	seg, err := logIDAPISegment(logID)
	if err != nil {
		f.t.Fatal(err)
	}
	return "GET " + hostOf(f.t, f.univ.URL) + "/api/logs/" + seg + "/authority"
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// The sealer asks univocity, and nobody else, for a log's root key: a lease
// is one authority read and one issuance, and when univocity cannot answer
// the lease fails having asked nobody else.
func TestDelegationLease_RootKeyComesOnlyFromUnivocity(t *testing.T) {
	logID := "4123456789abcdef0123456789abcdef"
	other := "5123456789abcdef0123456789abcdef"
	f := newAuthorityLeaseFixture(t, logID)

	if _, err := f.lease(logID); err != nil {
		t.Fatalf("lease: %v", err)
	}
	want := []string{f.authorityRequest(logID), "POST " + f.issuer + "/api/delegations"}
	if got := f.recorded.take(); !slices.Equal(got, want) {
		t.Fatalf("requests %q, want %q", got, want)
	}

	for _, status := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		f.univ.set(authorityAnswer{status: status})
		if _, err := f.lease(other); err == nil {
			t.Fatalf("status %d: lease succeeded without univocity's key", status)
		}
		want := []string{f.authorityRequest(other)}
		if got := f.recorded.take(); !slices.Equal(got, want) {
			t.Fatalf("status %d: requests %q, want %q", status, got, want)
		}
	}
}

// A log univocity reports pending is not sealed, and nothing else is asked
// for its key; it is retried, and sealed once univocity reports it anchored
// with every ancestor anchored too.
func TestDelegationLease_PendingLogRetriedUntilAnchored(t *testing.T) {
	logID := "6123456789abcdef0123456789abcdef"
	f := newAuthorityLeaseFixture(t, logID)
	owner := make([]byte, 16)
	owner[15] = 1

	for _, a := range []authorityAnswer{
		{state: "reserved"},
		{state: "committed"},
		{state: "committed", noKey: true},
		{state: "sequenced"},
		{state: "anchored", blockedBy: owner},
	} {
		f.univ.set(a)
		_, err := f.lease(logID)
		if !errors.Is(err, ErrAuthorityPending) || errors.Is(err, ErrLogConflicted) {
			t.Fatalf("%+v: got %v, want ErrAuthorityPending", a, err)
		}
		want := []string{f.authorityRequest(logID)}
		if got := f.recorded.take(); !slices.Equal(got, want) {
			t.Fatalf("%+v: requests %q, want %q", a, got, want)
		}
	}

	f.univ.set(authorityAnswer{state: "anchored", final: true})
	lease, err := f.lease(logID)
	if err != nil || lease == nil {
		t.Fatalf("anchored: lease=%v err=%v", lease, err)
	}
}

// A log univocity reports conflicted is final: it is not sealed, and the
// sealer does not ask about it again.
func TestDelegationLease_ConflictedLogIsFinal(t *testing.T) {
	logID := "7123456789abcdef0123456789abcdef"
	f := newAuthorityLeaseFixture(t, logID)

	f.univ.set(authorityAnswer{state: "conflicted", final: true})
	_, err := f.lease(logID)
	if !errors.Is(err, ErrLogConflicted) || errors.Is(err, ErrAuthorityPending) {
		t.Fatalf("got %v, want ErrLogConflicted", err)
	}

	f.univ.set(authorityAnswer{state: "anchored", final: true})
	for range 3 {
		if _, err := f.lease(logID); !errors.Is(err, ErrLogConflicted) {
			t.Fatalf("repeat: got %v, want ErrLogConflicted", err)
		}
	}
	if n := f.univ.requests(); n != 1 {
		t.Fatalf("univocity asked %d times, want 1", n)
	}
	if got := f.recorded.take(); len(got) != 1 {
		t.Fatalf("requests %q, want the one authority read", got)
	}
}

// The queue consumer and the resync act on a failed seal by its cause: a
// pending authority or delegation is retried later, a conflicted log's work
// is dropped and never retried, and anything else is a failure.
func TestClassifySealError(t *testing.T) {
	cases := []struct {
		err         error
		disposition SealDisposition
		reason      string
	}{
		{fmt.Errorf("resolve authority: %w", ErrAuthorityPending), SealDeferred, "authority_pending"},
		{fmt.Errorf("delegation issuer: %w", ErrDelegationPending), SealDeferred, "pending"},
		{fmt.Errorf("lease: %w", ErrDelegationExpired), SealDeferred, "expired"},
		{fmt.Errorf("resolve authority: %w", ErrLogConflicted), SealDropped, "conflicted"},
		{errors.New("r2 read failed"), SealFailed, ""},
	}
	for _, tc := range cases {
		d, reason := ClassifySealError(tc.err)
		if d != tc.disposition || reason != tc.reason {
			t.Errorf("%v: got (%v, %q), want (%v, %q)", tc.err, d, reason, tc.disposition, tc.reason)
		}
	}
}

// A lease taken while univocity's anchored answer is not yet final is used
// only briefly before univocity is asked again (devdocs ADR-0075,
// consequences), so a conflict found at the log's first checkpoint stops
// sealing promptly rather than when the lease expires. Once the answer is
// final the lease is used without asking.
func TestDelegationLease_NonFinalAuthorityIsRecheckedBriefly(t *testing.T) {
	logID := "8123456789abcdef0123456789abcdef"
	f := newAuthorityLeaseFixture(t, logID)
	f.univ.set(authorityAnswer{state: "anchored"})
	authority := []string{f.authorityRequest(logID)}

	if _, err := f.lease(logID); err != nil {
		t.Fatalf("lease: %v", err)
	}
	f.recorded.take()

	f.mgr.authorityRecheck = time.Hour
	if _, err := f.lease(logID); err != nil {
		t.Fatalf("reuse within the recheck interval: %v", err)
	}
	if got := f.recorded.take(); len(got) != 0 {
		t.Fatalf("reuse within the recheck interval asked %q, want nothing", got)
	}

	f.mgr.authorityRecheck = 0
	if _, err := f.lease(logID); err != nil {
		t.Fatalf("reuse after the recheck interval: %v", err)
	}
	if got := f.recorded.take(); !slices.Equal(got, authority) {
		t.Fatalf("reuse after the recheck interval asked %q, want %q", got, authority)
	}

	f.univ.set(authorityAnswer{state: "conflicted", final: true})
	if _, err := f.lease(logID); !errors.Is(err, ErrLogConflicted) {
		t.Fatalf("after a conflict: got %v, want ErrLogConflicted", err)
	}
	f.recorded.take()
	if _, err := f.lease(logID); !errors.Is(err, ErrLogConflicted) {
		t.Fatalf("after a conflict, again: got %v, want ErrLogConflicted", err)
	}
	if got := f.recorded.take(); len(got) != 0 {
		t.Fatalf("a conflicted log asked %q, want nothing", got)
	}
}

// Once univocity's answer is final, a held lease is used until it expires
// without asking univocity again.
func TestDelegationLease_FinalAuthorityIsNotRechecked(t *testing.T) {
	logID := "9123456789abcdef0123456789abcdef"
	f := newAuthorityLeaseFixture(t, logID)
	f.mgr.authorityRecheck = 0

	f.univ.set(authorityAnswer{state: "anchored"})
	if _, err := f.lease(logID); err != nil {
		t.Fatalf("lease: %v", err)
	}
	f.univ.set(authorityAnswer{state: "anchored", final: true})
	if _, err := f.lease(logID); err != nil {
		t.Fatalf("recheck: %v", err)
	}
	f.recorded.take()
	for range 3 {
		if _, err := f.lease(logID); err != nil {
			t.Fatalf("reuse: %v", err)
		}
	}
	if got := f.recorded.take(); len(got) != 0 {
		t.Fatalf("a final answer was rechecked: %q", got)
	}
}
