package univocity

import (
	"bytes"
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/arbor/services/pkgs/publishproof"
	"github.com/fxamacker/cbor/v2"
)

// claimFixture is a forest R whose contract is deployed, with univocity's
// write API mounted and a controllable clock.
type claimFixture struct {
	t     *testing.T
	api   *API
	store *fakeStore
	chain *mockChain
	logs  *memLogs
	mux   *http.ServeMux
	boot  *ecdsa.PrivateKey
	R     logid.UUID
	now   time.Time
}

func newClaimFixture(t *testing.T) *claimFixture {
	t.Helper()
	logger, _ := NewLogger(0)
	boot := mustKey(t)
	R := testLogID(1)
	store := newFakeStore()
	store.genesis[R.String()] = buildGenesisDoc(t, R, boot, 84532, common.HexToAddress("0xabc"))
	store.index[R.String()] = R
	chain := newChainColdAnchored(boot)
	f := &claimFixture{t: t, store: store, chain: chain, boot: boot, R: R,
		logs: newMemLogs(t), now: time.Unix(1_800_000_000, 0)}
	f.api = &API{
		Logger:         logger,
		Pool:           &mockPool{chain: chain},
		Store:          store,
		APIToken:       "secret",
		Bootstrap:      NewBootstrapCache(),
		ReservationTTL: 7 * 24 * time.Hour,
		Now:            func() time.Time { return f.now },
		Authorities:    NewAuthorityCache(100, 5*time.Minute),
		Massifs:        f.logs.readers(),
		Leaves:         publishproof.NewGrantLeafIndex(),
	}
	f.remount()
	return f
}

// remount re-registers the routes: handlers capture the API by value.
func (f *claimFixture) remount() {
	f.mux = http.NewServeMux()
	f.api.RegisterRoutes(f.mux)
}

// grant builds a create grant for subject, signed by signer as owner's key.
func (f *claimFixture) grant(subject, owner logid.UUID, signer *ecdsa.PrivateKey, key *ecdsa.PrivateKey) []byte {
	f.t.Helper()
	g := Grant{LogID: subject, OwnerLogID: owner, Flags: authLogFlags(), GrantData: xyConcat(key)}
	return buildGrantStatement(f.t, signer, g)
}

func (f *claimFixture) post(stmt []byte, intent string) *httptest.ResponseRecorder {
	f.t.Helper()
	body, err := cbor.Marshal(postGrantRequest{Statement: stmt, Intent: intent})
	if err != nil {
		f.t.Fatalf("encode request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/grants", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("%s: want %d got %d: %s", what, want, rec.Code, rec.Body.String())
	}
}

func TestPostGrant_CommittedGrantIsWriteOnce(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	first := f.grant(A, f.R, f.boot, mustKey(t))

	wantStatus(t, f.post(first, intentCommit), http.StatusCreated, "first commit")
	wantStatus(t, f.post(first, intentCommit), http.StatusOK, "same grant again")

	other := f.grant(A, f.R, f.boot, mustKey(t))
	rec := f.post(other, intentCommit)
	wantStatus(t, rec, http.StatusConflict, "different grant")
	if !bytes.Contains(rec.Body.Bytes(), []byte("grant-already-claimed")) {
		t.Fatalf("want grant-already-claimed problem, got %s", rec.Body.String())
	}
	stored, err := f.store.GetGrant(t.Context(), f.R, A)
	if err != nil || !bytes.Equal(stored, first) {
		t.Fatal("the first grant must stay stored")
	}
}

func decodeClaim(t *testing.T, rec *httptest.ResponseRecorder) postGrantResponse {
	t.Helper()
	var resp postGrantResponse
	if err := cbor.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode claim response: %v (%s)", err, rec.Body.String())
	}
	return resp
}

func TestPostGrant_ReservationHoldsTheLog(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	reserved := f.grant(A, f.R, f.boot, mustKey(t))

	rec := f.post(reserved, intentReserve)
	wantStatus(t, rec, http.StatusCreated, "reserve")
	resp := decodeClaim(t, rec)
	if resp.State != stateReserved || resp.ExpiresAt != f.now.Add(7*24*time.Hour).Unix() {
		t.Fatalf("reserve response %+v", resp)
	}

	other := f.grant(A, f.R, f.boot, mustKey(t))
	wantStatus(t, f.post(other, intentReserve), http.StatusConflict, "reserve a different grant")
	wantStatus(t, f.post(other, intentCommit), http.StatusConflict, "commit a different grant")

	// A reservation is not a committed claim: nothing public refers to it.
	if _, found, _ := f.store.IndexGet(t.Context(), A); found {
		t.Fatal("a reservation must not write the public logId->R index")
	}
	if _, err := f.store.GetGrant(t.Context(), f.R, A); err == nil {
		t.Fatal("a reservation must not write the public grant object")
	}
}

func TestPostGrant_RepostedReservationIsRefreshed(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	stmt := f.grant(A, f.R, f.boot, mustKey(t))
	wantStatus(t, f.post(stmt, intentReserve), http.StatusCreated, "reserve")

	f.now = f.now.Add(6 * 24 * time.Hour)
	rec := f.post(stmt, intentReserve)
	wantStatus(t, rec, http.StatusOK, "re-reserve")
	if got := decodeClaim(t, rec).ExpiresAt; got != f.now.Add(7*24*time.Hour).Unix() {
		t.Fatalf("refreshed expiresAt %d, want now+TTL", got)
	}

	// Past the original lapse time the refreshed reservation still holds.
	f.now = f.now.Add(2 * 24 * time.Hour)
	other := f.grant(A, f.R, f.boot, mustKey(t))
	wantStatus(t, f.post(other, intentReserve), http.StatusConflict, "reserve over a refreshed reservation")
}

func TestPostGrant_CommitConvertsReservation(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	stmt := f.grant(A, f.R, f.boot, mustKey(t))
	wantStatus(t, f.post(stmt, intentReserve), http.StatusCreated, "reserve")

	rec := f.post(stmt, intentCommit)
	wantStatus(t, rec, http.StatusOK, "commit the reserved grant")
	if got := decodeClaim(t, rec).State; got != stateCommitted {
		t.Fatalf("state %q, want committed", got)
	}
	if r, found, _ := f.store.IndexGet(t.Context(), A); !found || r != f.R {
		t.Fatal("a committed claim writes the logId->R index")
	}
	if stored, err := f.store.GetGrant(t.Context(), f.R, A); err != nil || !bytes.Equal(stored, stmt) {
		t.Fatal("a committed claim writes the grant object")
	}
	if len(f.store.reservations) != 0 {
		t.Fatal("the reservation is gone once committed")
	}
}

func TestReservation_LapsesWithEverythingBeneathIt(t *testing.T) {
	f := newClaimFixture(t)
	A, G, B := testLogID(2), testLogID(3), testLogID(4)
	aKey := mustKey(t)
	wantStatus(t, f.post(f.grant(A, f.R, f.boot, aKey), intentReserve), http.StatusCreated, "reserve child")

	// A whole hierarchy can be reserved before any of it is anchored.
	f.now = f.now.Add(24 * time.Hour)
	gStmt := f.grant(G, A, aKey, mustKey(t))
	wantStatus(t, f.post(gStmt, intentReserve), http.StatusCreated, "reserve grandchild")

	// Past A's lapse time, G's owner is unknown, so G's grant chain no
	// longer reaches the bootstrap key, though G's reservation has not lapsed.
	f.now = f.now.Add(6*24*time.Hour + time.Hour)
	wantStatus(t, f.post(gStmt, intentReserve), http.StatusBadRequest, "grandchild under a lapsed child")

	removed, err := f.api.SweepReservations(t.Context())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed != 2 || len(f.store.reservations) != 0 {
		t.Fatalf("sweep removed %d, left %d; want both reservations gone", removed, len(f.store.reservations))
	}

	// The lapsed log id is free again, for another owner.
	bKey := mustKey(t)
	wantStatus(t, f.post(f.grant(B, f.R, f.boot, bKey), intentCommit), http.StatusCreated, "commit owner B")
	wantStatus(t, f.post(f.grant(A, B, bKey, mustKey(t)), intentReserve), http.StatusCreated, "B claims A")
}

func TestReservation_CommittedClaimNeverLapses(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	stmt := f.grant(A, f.R, f.boot, mustKey(t))
	wantStatus(t, f.post(stmt, intentReserve), http.StatusCreated, "reserve")
	wantStatus(t, f.post(stmt, intentCommit), http.StatusOK, "commit")

	f.now = f.now.Add(10 * 365 * 24 * time.Hour)
	if _, err := f.api.SweepReservations(t.Context()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	other := f.grant(A, f.R, f.boot, mustKey(t))
	wantStatus(t, f.post(other, intentReserve), http.StatusConflict, "reserve over a committed claim")
	wantStatus(t, f.post(other, intentCommit), http.StatusConflict, "commit over a committed claim")
	if stored, err := f.store.GetGrant(t.Context(), f.R, A); err != nil || !bytes.Equal(stored, stmt) {
		t.Fatal("the committed grant stays stored")
	}
}

// The grant class is part of the grant, not a second claim: a committed
// data-log grant cannot be followed by an auth-log grant for the same log.
func TestPostGrant_OtherClassCannotReplaceCommittedGrant(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	dataLog := Grant{LogID: A, OwnerLogID: f.R, Flags: dataLogFlags(), GrantData: xyConcat(mustKey(t))}
	wantStatus(t, f.post(buildGrantStatement(t, f.boot, dataLog), intentCommit), http.StatusCreated, "commit data-log grant")

	rec := f.post(f.grant(A, f.R, f.boot, mustKey(t)), intentCommit)
	wantStatus(t, rec, http.StatusConflict, "commit auth-log grant for the same log")
	if !bytes.Contains(rec.Body.Bytes(), []byte("grant-already-claimed")) {
		t.Fatalf("want grant-already-claimed, got %s", rec.Body.String())
	}
	rec = f.post(f.grant(A, f.R, f.boot, mustKey(t)), intentReserve)
	wantStatus(t, rec, http.StatusConflict, "reserve auth-log grant for the same log")
}
