package univocity

import (
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/fxamacker/cbor/v2"
)

// These tests run univocity against the real univocity contract (release
// v0.3.0) on anvil: the contract's ABI, its LogRegistered event and its
// logConfig decoding, rather than a mock chain. A log whose first
// registration on chain differs from univocity's claim is conflicted, final,
// and raises the alarm (devdocs ADR-0075 decision 8).

// univocityOnAnvil is a deployed forest R with univocity wired to it.
type univocityOnAnvil struct {
	t      *testing.T
	f      *avForest
	api    *API
	store  *fakeStore
	mux    *http.ServeMux
	forest ForestEntry
}

func newUnivocityOnAnvil(t *testing.T) *univocityOnAnvil {
	t.Helper()
	R := testLogID(1)
	f := newAvForest(t, R)
	f.publishRoot()

	pool, err := NewContractClients(map[uint64]string{f.chain.chainID.Uint64(): f.rpcURL})
	if err != nil {
		t.Fatal(err)
	}
	logger, _ := NewLogger(0)
	store := newFakeStore()
	// The genesis key must equal the contract's bootstrap key.
	store.genesis[R.String()] = buildGenesisDocKS256(t, R, f.rootKey, f.chain.chainID.Uint64(), f.chain.contract)
	store.index[R.String()] = R
	u := &univocityOnAnvil{t: t, f: f, store: store, api: &API{
		Logger:      logger,
		Pool:        pool,
		Store:       store,
		Bootstrap:   NewBootstrapCache(),
		Authorities: NewAuthorityCache(100, 5*time.Minute),
	}}
	forest, _, err := u.api.resolveForestForLog(t.Context(), R, logid.UUID{})
	if err != nil {
		t.Fatalf("resolve forest: %v", err)
	}
	u.forest = forest
	u.remount()
	return u
}

func (u *univocityOnAnvil) remount() {
	u.mux = http.NewServeMux()
	u.api.RegisterRoutes(u.mux)
}

// claim commits univocity's claim for subject: owner and key.
func (u *univocityOnAnvil) claim(subject, owner logid.UUID, key *ecdsa.PrivateKey) {
	u.t.Helper()
	stmt := buildGrantStatementKS256(u.t, u.f.rootKey, Grant{
		LogID: subject, OwnerLogID: owner, Flags: authLogFlags(),
		GrantData: crypto.PubkeyToAddress(key.PublicKey).Bytes(),
	})
	u.store.grants[u.store.grantStoreKey(u.f.R, subject, GrantClassAuthLog)] = stmt
	u.store.index[subject.String()] = u.f.R
}

func (u *univocityOnAnvil) authority(id logid.UUID) authorityResponse {
	u.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/logs/"+id.String()+"/authority", nil)
	rec := httptest.NewRecorder()
	u.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		u.t.Fatalf("authority %s: %d %s", id, rec.Code, rec.Body.String())
	}
	var resp authorityResponse
	if err := cbor.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		u.t.Fatalf("decode authority: %v", err)
	}
	return resp
}

func (u *univocityOnAnvil) want(resp authorityResponse, state string, owner logid.UUID, key *ecdsa.PrivateKey) {
	u.t.Helper()
	if resp.State != state || !resp.Final {
		u.t.Fatalf("state %q final=%v, want %q final", resp.State, resp.Final, state)
	}
	if string(resp.OwnerLogID) != string(owner[:]) && string(resp.OwnerLogID) != string(paddedWire(owner)) {
		u.t.Fatalf("ownerLogId %x, want %s", resp.OwnerLogID, owner)
	}
	if want := crypto.PubkeyToAddress(key.PublicKey).Bytes(); string(resp.Key) != string(want) {
		u.t.Fatalf("key %x, want %x", resp.Key, want)
	}
}

func paddedWire(id logid.UUID) []byte { w := id.ToPaddedWire32(); return w[:] }

func TestAnvilConflict_DifferentOwner(t *testing.T) {
	u := newUnivocityOnAnvil(t)
	R, A, C := u.f.R, testLogID(2), testLogID(3)
	K := mustKS256Key(t)
	u.claim(A, R, mustKS256Key(t)) // A exists only as a claim
	u.claim(C, A, K)               // univocity believes C is owned by A

	alarms := ConflictsDetected()
	u.f.registerChild(C, K) // the chain registers C under owner R
	resp := u.authority(C)
	u.want(resp, stateConflicted, R, K)
	if got := ConflictsDetected(); got != alarms+1 {
		t.Fatalf("conflicts detected %d, want %d", got, alarms+1)
	}
}

func TestAnvilConflict_DifferentKey(t *testing.T) {
	u := newUnivocityOnAnvil(t)
	R, C := u.f.R, testLogID(3)
	K1, K2 := mustKS256Key(t), mustKS256Key(t)
	u.claim(C, R, K1)

	alarms := ConflictsDetected()
	u.f.registerChild(C, K2)
	u.want(u.authority(C), stateConflicted, R, K2)
	if got := ConflictsDetected(); got != alarms+1 {
		t.Fatalf("conflicts detected %d, want %d", got, alarms+1)
	}
}

func TestAnvilConflict_MatchingClaimIsAnchored(t *testing.T) {
	u := newUnivocityOnAnvil(t)
	R, C := u.f.R, testLogID(3)
	K := mustKS256Key(t)
	u.claim(C, R, K)

	alarms := ConflictsDetected()
	u.f.registerChild(C, K)
	u.want(u.authority(C), stateAnchored, R, K)
	if got := ConflictsDetected(); got != alarms {
		t.Fatalf("conflicts detected %d, want %d", got, alarms)
	}
}

// The watcher finds the registration from the LogRegistered event, raises the
// alarm once, and the cached final answer does not raise it again.
func TestAnvilConflict_WatcherDetectsRegistration(t *testing.T) {
	u := newUnivocityOnAnvil(t)
	R, C := u.f.R, testLogID(3)
	K1, K2 := mustKS256Key(t), mustKS256Key(t)
	u.claim(C, R, K1)

	u.api.Registrations = NewRegistrationWatcher()
	u.api.Registrations.watch(u.forest)
	u.api.pollRegistrations(t.Context()) // first poll: catches up to the head
	u.remount()

	alarms := ConflictsDetected()
	u.f.registerChild(C, K2)
	u.api.pollRegistrations(t.Context())
	if got := ConflictsDetected(); got != alarms+1 {
		t.Fatalf("watcher: conflicts detected %d, want %d", got, alarms+1)
	}
	u.want(u.authority(C), stateConflicted, R, K2)
	if got := ConflictsDetected(); got != alarms+1 {
		t.Fatalf("read after watcher: conflicts detected %d, want %d (answer is final)", got, alarms+1)
	}
}
