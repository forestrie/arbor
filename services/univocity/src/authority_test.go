package univocity

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/fxamacker/cbor/v2"
)

func (f *claimFixture) authority(id string) (authorityResponse, *httptest.ResponseRecorder) {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/logs/"+id+"/authority", nil)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	var resp authorityResponse
	if rec.Code == http.StatusOK {
		if err := cbor.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			f.t.Fatalf("decode authority: %v", err)
		}
	}
	return resp, rec
}

// A root's key comes only from its contract, so a root whose contract is not
// deployed has no key and is not anchored (protocol ADR-0070 decision 1).
func TestAuthority_RootWithoutContractIsPending(t *testing.T) {
	f := newClaimFixture(t)
	f.api.Pool = &mockPool{chain: mockChainEmptyResponse{}}
	f.remount()

	resp, rec := f.authority(f.R.String())
	wantStatus(t, rec, http.StatusOK, "root authority")
	if resp.State == stateAnchored || resp.Final || len(resp.Key) != 0 {
		t.Fatalf("undeployed root reported %+v; want pending with no key", resp)
	}
}

func TestAuthority_RootOnChainIsAnchoredAndFinal(t *testing.T) {
	f := newClaimFixture(t)
	f.chain.rootLogId = f.R

	resp, rec := f.authority(f.R.String())
	wantStatus(t, rec, http.StatusOK, "root authority")
	if resp.State != stateAnchored || !resp.Final || resp.Alg != coseAlgES256 ||
		string(resp.Key) != string(xyConcat(f.boot)) {
		t.Fatalf("root on chain reported %+v; want anchored, final, bootstrap key", resp)
	}
}

// Before the root's first checkpoint the contract records no root, so the
// root is anchored (its key is the contract's, and the sealer needs it to
// seal that first checkpoint) but not final: another forest bound to the
// same contract could still publish first.
func TestAuthority_RootBeforeItsFirstCheckpointIsAnchoredNotFinal(t *testing.T) {
	f := newClaimFixture(t)

	resp, rec := f.authority(f.R.String())
	wantStatus(t, rec, http.StatusOK, "root authority")
	if resp.State != stateAnchored || resp.Final ||
		string(resp.Key) != string(xyConcat(f.boot)) {
		t.Fatalf("root before its first checkpoint reported %+v; want anchored, not final, bootstrap key", resp)
	}
}

// A contract takes one root: the first root checkpoint published to it
// (platform rule P14). A forest whose genesis names a contract that another
// log already roots can never publish there, so its root is conflicted, and
// final.
func TestAuthority_RootOfAContractRootedElsewhereIsConflicted(t *testing.T) {
	f := newClaimFixture(t)
	f.chain.rootLogId = testLogID(99)

	resp, rec := f.authority(f.R.String())
	wantStatus(t, rec, http.StatusOK, "root authority")
	if resp.State != stateConflicted || !resp.Final {
		t.Fatalf("root of a contract rooted elsewhere reported %+v; want conflicted, final", resp)
	}
}

// A committed child of a root whose contract records another root can
// never anchor: no checkpoint of that root can publish there. The conflict
// is final, so the child's answer is too, with the root as blockedBy;
// callers stop waiting on it.
func TestAuthority_CommittedChildOfAConflictedRootIsFinal(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(47)
	wantStatus(t, f.post(f.grant(A, f.R, f.boot, mustKey(t)), intentCommit),
		http.StatusCreated, "commit A")
	f.chain.rootLogId = testLogID(99)
	f.api.Authorities.evict(f.R) // as the watcher does at the other root's registration

	resp, rec := f.authority(A.String())
	wantStatus(t, rec, http.StatusOK, "child authority")
	if !resp.Final || !bytes.Equal(resp.BlockedBy, f.R[:]) {
		t.Fatalf("child of a conflicted root reported %+v; want final, blockedBy R", resp)
	}
}

// A reservation can lapse and its log be claimed elsewhere, so a reserved
// child of a conflicted root is not final.
func TestAuthority_ReservedChildOfAConflictedRootIsNotFinal(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(48)
	wantStatus(t, f.post(f.grant(A, f.R, f.boot, mustKey(t)), intentReserve),
		http.StatusCreated, "reserve A")
	f.chain.rootLogId = testLogID(99)
	f.api.Authorities.evict(f.R)

	resp, rec := f.authority(A.String())
	wantStatus(t, rec, http.StatusOK, "child authority")
	if resp.Final || !bytes.Equal(resp.BlockedBy, f.R[:]) {
		t.Fatalf("reserved child of a conflicted root reported %+v; want not final, blockedBy R", resp)
	}
}

// publishRoot marks the forest root as published on chain at size. Its first
// checkpoint makes it the contract's root, and the LogRegistered watcher
// then drops its answer from before (TestRegistrationWatcher_RootTurnsFinal).
func (f *claimFixture) publishRoot(size uint64) {
	f.t.Helper()
	f.chain.rootLogId = f.R
	f.api.Authorities.evict(f.R)
	f.chain.setLog(f.R, mockLog{
		config: LogConfig{Kind: LogKindAuthority, AuthLogId: f.R, RootKey: xyConcat(f.boot)},
		state:  f.logs.published(f.R, size),
	})
}

func wantState(t *testing.T, resp authorityResponse, state string, what string) {
	t.Helper()
	if resp.State != state {
		t.Fatalf("%s: state %q, want %q (%+v)", what, resp.State, state, resp)
	}
}

func TestAuthority_ChildProgressesFromReservedToAnchored(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	aKey := mustKey(t)
	stmt := f.grant(A, f.R, f.boot, aKey)

	wantStatus(t, f.post(stmt, intentReserve), http.StatusCreated, "reserve")
	resp, rec := f.authority(A.String())
	wantStatus(t, rec, http.StatusOK, "authority")
	wantState(t, resp, stateReserved, "prepared")
	if resp.ExpiresAt != f.now.Add(7*24*time.Hour).Unix() || string(resp.Key) != string(xyConcat(aKey)) || resp.Final {
		t.Fatalf("reserved answer %+v", resp)
	}

	wantStatus(t, f.post(stmt, intentCommit), http.StatusOK, "commit")
	resp, _ = f.authority(A.String())
	wantState(t, resp, stateCommitted, "registered")

	// Ranger sequences the create grant into the owner's log. Nothing tells
	// univocity its idtimestamp; the leaf scan finds it.
	f.logs.appendLeaf(f.R, [32]byte{1})
	size := f.logs.appendLeaf(f.R, contentHashOf(t, stmt))
	resp, _ = f.authority(A.String())
	wantState(t, resp, stateSequenced, "sequenced")

	// A published checkpoint of the owner below the leaf does not cover it.
	f.publishRoot(1)
	resp, _ = f.authority(A.String())
	wantState(t, resp, stateSequenced, "checkpoint before the leaf")

	f.publishRoot(size)
	resp, _ = f.authority(A.String())
	wantState(t, resp, stateAnchored, "covered by a published checkpoint")
	if resp.Final || len(resp.BlockedBy) != 0 || string(resp.Key) != string(xyConcat(aKey)) {
		t.Fatalf("anchored answer %+v; want not final, unblocked, grantData key", resp)
	}
}

func TestAuthority_GrandchildIsBlockedByItsPendingParent(t *testing.T) {
	f := newClaimFixture(t)
	A, G := testLogID(2), testLogID(3)
	aKey := mustKey(t)
	aStmt := f.grant(A, f.R, f.boot, aKey)
	wantStatus(t, f.post(aStmt, intentCommit), http.StatusCreated, "commit A")
	wantStatus(t, f.post(f.grant(G, A, aKey, mustKey(t)), intentReserve), http.StatusCreated, "reserve G")

	resp, _ := f.authority(G.String())
	wantState(t, resp, stateReserved, "grandchild")
	if string(resp.BlockedBy) != string(A[:]) {
		t.Fatalf("blockedBy %x, want parent %s", resp.BlockedBy, A)
	}

	f.publishRoot(f.logs.appendLeaf(f.R, contentHashOf(t, aStmt)))
	resp, _ = f.authority(G.String())
	if len(resp.BlockedBy) != 0 {
		t.Fatalf("blockedBy %x once the parent is anchored, want none", resp.BlockedBy)
	}
}

// canopy refuses first; univocity's refusal is the backstop, so a committed
// claim always has an anchored owner (devdocs ADR-0075 decision 8).
func TestPostGrant_CommitUnderPendingOwnerIsRefused(t *testing.T) {
	f := newClaimFixture(t)
	A, G := testLogID(2), testLogID(3)
	aKey := mustKey(t)
	aStmt := f.grant(A, f.R, f.boot, aKey)
	wantStatus(t, f.post(aStmt, intentCommit), http.StatusCreated, "commit A")

	gStmt := f.grant(G, A, aKey, mustKey(t))
	rec := f.post(gStmt, intentCommit)
	wantStatus(t, rec, http.StatusConflict, "commit under a pending owner")
	if !bytes.Contains(rec.Body.Bytes(), []byte("owner-not-anchored")) {
		t.Fatalf("want owner-not-anchored, got %s", rec.Body.String())
	}
	if _, found, _ := f.store.IndexGet(t.Context(), G); found {
		t.Fatal("a refused commit claims nothing")
	}

	f.publishRoot(f.logs.appendLeaf(f.R, contentHashOf(t, aStmt)))
	wantStatus(t, f.post(gStmt, intentCommit), http.StatusCreated, "commit once the owner is anchored")
}

// The chain is read when a log anchors, not once per statement (protocol
// ADR-0070 decision 3).
func TestAuthority_RepeatReadOfAnchoredLogMakesNoChainCall(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	stmt := f.grant(A, f.R, f.boot, mustKey(t))
	wantStatus(t, f.post(stmt, intentCommit), http.StatusCreated, "commit")
	f.publishRoot(f.logs.appendLeaf(f.R, contentHashOf(t, stmt)))

	for _, id := range []string{f.R.String(), A.String()} {
		resp, _ := f.authority(id)
		wantState(t, resp, stateAnchored, "first read "+id)
		before := f.chain.callCount()
		resp, _ = f.authority(id)
		wantState(t, resp, stateAnchored, "repeat read "+id)
		if got := f.chain.callCount() - before; got != 0 {
			t.Fatalf("repeat read of anchored %s made %d chain calls", id, got)
		}
	}
}

// anchoredChild commits and anchors a child of R, returning its key.
func (f *claimFixture) anchoredChild(A logid.UUID) *ecdsa.PrivateKey {
	f.t.Helper()
	key := mustKey(f.t)
	stmt := f.grant(A, f.R, f.boot, key)
	wantStatus(f.t, f.post(stmt, intentCommit), http.StatusCreated, "commit "+A.String())
	f.publishRoot(f.logs.appendLeaf(f.R, contentHashOf(f.t, stmt)))
	return key
}

func (f *claimFixture) registerOnChain(id, owner logid.UUID, key []byte) {
	f.chain.setLog(id, mockLog{config: LogConfig{Kind: LogKindData, AuthLogId: owner, RootKey: key}})
}

func TestAuthority_FirstRegistrationMatchingClaimIsFinal(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	key := f.anchoredChild(A)
	f.registerOnChain(A, f.R, xyConcat(key))

	resp, _ := f.authority(A.String())
	wantState(t, resp, stateAnchored, "registered as claimed")
	if !resp.Final || resp.Source != "chain" {
		t.Fatalf("matching first registration %+v; want final, from chain", resp)
	}
}

func TestAuthority_FirstRegistrationDifferingFromClaimIsConflicted(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner func(f *claimFixture) logid.UUID
		key   func(claimed *ecdsa.PrivateKey) []byte
	}{
		{"other owner", func(*claimFixture) logid.UUID { return testLogID(9) },
			func(k *ecdsa.PrivateKey) []byte { return xyConcat(k) }},
		{"other key", func(f *claimFixture) logid.UUID { return f.R },
			func(*ecdsa.PrivateKey) []byte { return xyConcat(mustKey(t)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newClaimFixture(t)
			A, C := testLogID(2), testLogID(3)
			key := f.anchoredChild(A)
			wantStatus(t, f.post(f.grant(C, A, key, mustKey(t)), intentReserve), http.StatusCreated, "reserve C")

			// An anchored answer given before the log's first checkpoint.
			resp, _ := f.authority(A.String())
			wantState(t, resp, stateAnchored, "before first checkpoint")

			chainOwner, chainKey := tc.owner(f), tc.key(key)
			alarms := ConflictsDetected()
			f.registerOnChain(A, chainOwner, chainKey)
			f.now = f.now.Add(10 * time.Minute) // past the anchored re-check

			resp, _ = f.authority(A.String())
			wantState(t, resp, stateConflicted, "after a differing first registration")
			if !resp.Final || string(resp.OwnerLogID) != string(chainOwner[:]) || string(resp.Key) != string(chainKey) {
				t.Fatalf("conflicted answer %+v; want final with the chain's owner and key", resp)
			}
			if ConflictsDetected() != alarms+1 {
				t.Fatal("a conflict must raise the alarm")
			}

			// Children report it, and it never changes after.
			child, _ := f.authority(C.String())
			if string(child.BlockedBy) != string(A[:]) {
				t.Fatalf("child blockedBy %x, want conflicted parent", child.BlockedBy)
			}
			f.registerOnChain(A, f.R, xyConcat(key))
			f.now = f.now.Add(24 * time.Hour)
			resp, _ = f.authority(A.String())
			wantState(t, resp, stateConflicted, "later")
		})
	}
}

// A root read before its first checkpoint is anchored but not final, and is
// cached until re-check. Its own LogRegistered event makes it final at once.
func TestRegistrationWatcher_RootTurnsFinal(t *testing.T) {
	f := newClaimFixture(t)
	w := NewRegistrationWatcher()
	f.api.Registrations = w
	f.remount()
	resp, _ := f.authority(f.R.String())
	if resp.State != stateAnchored || resp.Final {
		t.Fatalf("root before its first checkpoint %+v; want anchored, not final", resp)
	}
	f.api.pollRegistrations(t.Context()) // first poll: catches up to the head

	f.chain.rootLogId = f.R
	f.chain.emitRegistration(f.R, f.R)
	f.api.pollRegistrations(t.Context())

	resp, _ = f.authority(f.R.String())
	if resp.State != stateAnchored || !resp.Final {
		t.Fatalf("root after its first checkpoint %+v; want anchored, final", resp)
	}
}

// Two forests bound to one contract: the root that publishes first takes
// the contract, and the other can never publish there. When the winner's
// registration is seen, the loser's anchored answer is dropped and it reads
// conflicted at once, not after the anchored recheck.
func TestRegistrationWatcher_LosingRootTurnsConflicted(t *testing.T) {
	f := newClaimFixture(t)
	f.api.Registrations = NewRegistrationWatcher()
	f.remount()
	resp, _ := f.authority(f.R.String())
	if resp.State != stateAnchored || resp.Final {
		t.Fatalf("root before any checkpoint %+v; want anchored, not final", resp)
	}
	f.api.pollRegistrations(t.Context()) // first poll: catches up to the head

	winner := testLogID(99)
	f.chain.rootLogId = winner
	f.chain.emitRegistration(winner, winner)
	f.api.pollRegistrations(t.Context())

	resp, _ = f.authority(f.R.String())
	if resp.State != stateConflicted || !resp.Final {
		t.Fatalf("root after another root took its contract %+v; want conflicted, final", resp)
	}
}

// The LogRegistered watcher compares a claimed log with the chain as soon as
// it is registered, without waiting for a read or the anchored re-check.
func TestRegistrationWatcher_DetectsConflictAtRegistration(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	f.anchoredChild(A)
	resp, _ := f.authority(A.String())
	wantState(t, resp, stateAnchored, "before registration")

	w := NewRegistrationWatcher()
	f.api.Registrations = w
	f.remount()
	forest, _, err := f.api.resolveForestForLog(t.Context(), A, logid.UUID{})
	if err != nil {
		t.Fatalf("resolve forest: %v", err)
	}
	w.watch(forest)
	f.api.pollRegistrations(t.Context()) // first poll: catches up to the head

	alarms := ConflictsDetected()
	other := testLogID(9)
	f.registerOnChain(A, other, xyConcat(mustKey(t)))
	f.chain.emitRegistration(A, other)
	f.api.pollRegistrations(t.Context())

	if ConflictsDetected() != alarms+1 {
		t.Fatal("the watcher must raise the alarm at registration")
	}
	resp, _ = f.authority(A.String())
	wantState(t, resp, stateConflicted, "after the watcher saw the registration")
}

// A final answer is cached for good only when nothing above it can still
// change: an ancestor that is merely pending (here, a root whose chain read
// failed) must not be frozen into a child's answer.
func TestAuthority_FinalAnswerBlockedByPendingAncestorIsNotKeptForGood(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	key := f.anchoredChild(A)
	f.registerOnChain(A, f.R, xyConcat(key))

	// A fresh process whose first chain read of the root fails.
	f.api.Bootstrap = NewBootstrapCache()
	f.api.Authorities = NewAuthorityCache(100, 5*time.Minute)
	f.chain.bootstrapErr = errors.New("rpc unavailable")
	f.remount()
	resp, _ := f.authority(A.String())
	if string(resp.BlockedBy) != string(f.R[:]) {
		t.Fatalf("blockedBy %x while the root is unreadable, want R", resp.BlockedBy)
	}

	f.chain.bootstrapErr = nil
	resp, _ = f.authority(A.String())
	wantState(t, resp, stateAnchored, "once the root is readable")
	if !resp.Final || len(resp.BlockedBy) != 0 {
		t.Fatalf("answer %+v; want final and unblocked once the root is readable", resp)
	}
}

// Conflicted is detected once: a later LogRegistered event for the same log
// does not raise the alarm again.
func TestAuthority_ConflictAlarmsOnce(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	f.anchoredChild(A)
	f.api.Registrations = NewRegistrationWatcher()
	f.remount()
	forest, _, err := f.api.resolveForestForLog(t.Context(), A, logid.UUID{})
	if err != nil {
		t.Fatalf("resolve forest: %v", err)
	}
	f.api.Registrations.watch(forest)
	f.api.pollRegistrations(t.Context())

	alarms := ConflictsDetected()
	f.registerOnChain(A, testLogID(9), xyConcat(mustKey(t)))
	resp, _ := f.authority(A.String())
	wantState(t, resp, stateConflicted, "read after registration")
	f.chain.emitRegistration(A, testLogID(9))
	f.api.pollRegistrations(t.Context())
	if got := ConflictsDetected() - alarms; got != 1 {
		t.Fatalf("conflict alarmed %d times, want once", got)
	}
}

// A child's answer is final only once every answer it rests on is final:
// an owner anchored by its create grant's leaf can still turn conflicted at
// its own first checkpoint, and the child must then report it.
func TestAuthority_ChildIsNotFinalWhileItsOwnerCanStillConflict(t *testing.T) {
	f := newClaimFixture(t)
	A, C := testLogID(2), testLogID(3)
	aKey := f.anchoredChild(A)
	cKey := mustKey(t)
	wantStatus(t, f.post(f.grant(C, A, aKey, cKey), intentCommit), http.StatusCreated, "commit C under A")
	f.registerOnChain(C, A, xyConcat(cKey))

	f.api.Registrations = NewRegistrationWatcher()
	f.remount()
	forest, _, err := f.api.resolveForestForLog(t.Context(), A, logid.UUID{})
	if err != nil {
		t.Fatalf("resolve forest: %v", err)
	}
	f.api.Registrations.watch(forest)
	f.api.pollRegistrations(t.Context())

	resp, _ := f.authority(A.String())
	wantState(t, resp, stateAnchored, "A by its leaf")
	resp, _ = f.authority(C.String())
	wantState(t, resp, stateAnchored, "C on chain as claimed")
	if resp.Final {
		t.Fatal("C is final while its owner A can still conflict")
	}

	// A's first checkpoint registers it under another owner.
	f.registerOnChain(A, testLogID(9), xyConcat(aKey))
	f.chain.emitRegistration(A, testLogID(9))
	f.api.pollRegistrations(t.Context())

	resp, _ = f.authority(C.String())
	if string(resp.BlockedBy) != string(A[:]) {
		t.Fatalf("C blockedBy %x after A conflicted, want A", resp.BlockedBy)
	}
}

// The owner may grow and publish between the leaf scan and the proof; the
// proof must read the owner's log as published, not the scan's view of it.
func TestAuthority_ProofReadsTheOwnerLogAsPublished(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	stmt := f.grant(A, f.R, f.boot, mustKey(t))
	wantStatus(t, f.post(stmt, intentCommit), http.StatusCreated, "commit")
	f.logs.appendLeaf(f.R, contentHashOf(t, stmt))

	f.chain.beforeLogState = func() {
		var size uint64
		// Stay within the first massif (height 3: four leaves).
		for i := range 2 {
			size = f.logs.appendLeaf(f.R, [32]byte{byte(i + 1)})
		}
		f.publishRoot(size)
	}
	resp, rec := f.authority(A.String())
	wantStatus(t, rec, http.StatusOK, "authority")
	wantState(t, resp, stateAnchored, "covered by a checkpoint published after the scan")
}

// Only a contract that is not deployed makes the root pending. A failed
// read of a deployed contract is an outage, not an answer.
func TestAuthority_ChainOutageIsAnErrorNotPending(t *testing.T) {
	f := newClaimFixture(t)
	f.api.Bootstrap = NewBootstrapCache()
	f.chain.code = map[common.Address]bool{common.HexToAddress("0xabc"): true}
	f.chain.bootstrapErr = errors.New("rpc unavailable")
	f.remount()

	_, rec := f.authority(f.R.String())
	if rec.Code < 500 {
		t.Fatalf("root authority during an outage: %d %s, want 5xx", rec.Code, rec.Body.String())
	}
}

// A conflicted owner never anchors: the backstop says so, rather than
// asking the caller to wait.
func TestPostGrant_CommitUnderConflictedOwnerIsRefusedAsConflict(t *testing.T) {
	f := newClaimFixture(t)
	A, G := testLogID(2), testLogID(3)
	aKey := f.anchoredChild(A)
	f.registerOnChain(A, testLogID(9), xyConcat(aKey))

	rec := f.post(f.grant(G, A, aKey, mustKey(t)), intentCommit)
	wantStatus(t, rec, http.StatusConflict, "commit under a conflicted owner")
	if !bytes.Contains(rec.Body.Bytes(), []byte("authority-conflict")) {
		t.Fatalf("want authority-conflict, got %s", rec.Body.String())
	}
}

// A registration between univocity loading the forest and the watcher's
// first poll is not skipped.
func TestRegistrationWatcher_SeesRegistrationsBeforeItsFirstPoll(t *testing.T) {
	f := newClaimFixture(t)
	A := testLogID(2)
	f.anchoredChild(A)
	f.api.Registrations = NewRegistrationWatcher()
	f.remount()
	forest, _, err := f.api.resolveForestForLog(t.Context(), A, logid.UUID{})
	if err != nil {
		t.Fatalf("resolve forest: %v", err)
	}
	f.api.Registrations.watch(forest)

	alarms := ConflictsDetected()
	f.registerOnChain(A, testLogID(9), xyConcat(mustKey(t)))
	f.chain.emitRegistration(A, testLogID(9))
	f.api.pollRegistrations(t.Context())
	if ConflictsDetected() != alarms+1 {
		t.Fatal("the first poll skipped a registration made after the forest was loaded")
	}
}
