package univocity

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/arbor/services/pkgs/publishproof"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/fxamacker/cbor/v2"
)

// A child log's create grant is claimed through univocity once (devdocs
// ADR-0075 decisions 1 and 2). A committed claim is the grant object at
// forests/forest/{R}/grants/{class}/{subject}.cbor plus the logId->R index
// entry, both written once and both read publicly (publishproof resolves
// and publishes from them). A reservation, made by canopy's prepare, is a
// private record holding the grant and its lapse time; nothing public
// refers to it, so letting it lapse never touches a committed claim.

// Claim intents posted with a create grant.
const (
	// intentReserve comes from canopy's prepare: the grant is not sequenced.
	intentReserve = "reserve"
	// intentCommit comes from register-grant: the grant is about to be
	// sequenced, so the claim must never lapse.
	intentCommit = "commit"
)

// Claim states reported for a claimed log.
const (
	stateReserved  = "reserved"
	stateCommitted = "committed"
)

var (
	// errGrantAlreadyClaimed: a different create grant holds the log's claim.
	errGrantAlreadyClaimed = errors.New("a different create grant has claimed this log")
	// errLogInOtherForest: the log id is claimed in another forest.
	errLogInOtherForest = errors.New("global logId->R uniqueness violated")
)

// claimResult reports the outcome of a claim request.
type claimResult struct {
	// created is true when the log id was unclaimed before this request.
	created   bool
	state     string
	expiresAt time.Time
}

// reservationRecord is the stored form of a reservation.
type reservationRecord struct {
	RootLogID []byte `cbor:"rootLogId"`
	Statement []byte `cbor:"statement"`
	// ExpiresAt is the lapse time in Unix seconds.
	ExpiresAt int64 `cbor:"expiresAt"`
}

// reservation is a decoded reservation record and the version it was read at.
type reservation struct {
	root      logid.UUID
	statement []byte
	expiresAt time.Time
	version   string
}

// maxClaimRaces bounds retries when a reservation changes under a writer.
const maxClaimRaces = 4

// readReservation returns subject's reservation, or found=false.
func (a API) readReservation(ctx context.Context, subject logid.UUID) (reservation, bool, error) {
	body, version, err := a.Store.GetReservation(ctx, subject)
	if isStoreMiss(err) {
		return reservation{}, false, nil
	}
	if err != nil {
		return reservation{}, false, fmt.Errorf("read reservation: %w", err)
	}
	var rec reservationRecord
	if err := cbor.Unmarshal(body, &rec); err != nil {
		return reservation{}, false, fmt.Errorf("decode reservation: %w", err)
	}
	root, err := logid.FromBytes(rec.RootLogID)
	if err != nil {
		return reservation{}, false, fmt.Errorf("reservation rootLogId: %w", err)
	}
	return reservation{
		root:      root,
		statement: rec.Statement,
		expiresAt: time.Unix(rec.ExpiresAt, 0),
		version:   version,
	}, true, nil
}

// live reports whether the reservation has not lapsed at now. Reads treat a
// lapsed reservation as absent before the sweep removes it.
func (r reservation) live(now time.Time) bool {
	return now.Before(r.expiresAt)
}

// checkHeldBy refuses a claim on a log a live reservation holds for another
// forest or another grant.
func (r reservation) checkHeldBy(root logid.UUID, posted []byte) error {
	if r.root != root {
		return errLogInOtherForest
	}
	return requireSameGrant(r.statement, posted)
}

// reserveClaim reserves subject in forest root for ts until now+TTL, or
// refreshes the same grant's reservation. A committed claim for the same
// grant already holds more than a reservation and is reported as it is.
func (a API) reserveClaim(
	ctx context.Context,
	root logid.UUID,
	ts TransparentStatement,
) (claimResult, error) {
	subject := ts.Grant.LogID
	defer lockSubject(subject)()

	if err := a.refuseForestRoot(ctx, root, subject); err != nil {
		return claimResult{}, err
	}
	indexed, found, err := a.Store.IndexGet(ctx, subject)
	if err != nil {
		return claimResult{}, fmt.Errorf("index lookup: %w", err)
	}
	if found && indexed != root {
		return claimResult{}, errLogInOtherForest
	}
	if found {
		stored, err := a.Store.GetGrant(ctx, root, subject)
		if err == nil {
			if err := requireSameGrant(stored, ts.Raw); err != nil {
				return claimResult{}, err
			}
			return claimResult{state: stateCommitted}, nil
		}
		if !isStoreMiss(err) {
			return claimResult{}, fmt.Errorf("read claimed grant: %w", err)
		}
	}

	for range maxClaimRaces {
		now := a.now()
		res, held, err := a.readReservation(ctx, subject)
		if err != nil {
			return claimResult{}, err
		}
		version := ""
		created := true
		if held {
			version = res.version
			if res.live(now) {
				if err := res.checkHeldBy(root, ts.Raw); err != nil {
					return claimResult{}, err
				}
				created = false
			}
		}
		expiresAt := now.Add(a.reservationTTL())
		body, err := canonicalCBOR.Marshal(reservationRecord{
			RootLogID: root[:],
			Statement: ts.Raw,
			ExpiresAt: expiresAt.Unix(),
		})
		if err != nil {
			return claimResult{}, fmt.Errorf("encode reservation: %w", err)
		}
		err = a.Store.PutReservation(ctx, subject, body, version)
		if errors.Is(err, ErrReservationChanged) {
			continue
		}
		if err != nil {
			return claimResult{}, err
		}
		return claimResult{created: created, state: stateReserved, expiresAt: expiresAt}, nil
	}
	return claimResult{}, ErrReservationChanged
}

// subjectLocks serialises claim writes per log id within this process.
// Conditional puts keep claims consistent across processes.
var subjectLocks sync.Map

func lockSubject(subject logid.UUID) func() {
	v, _ := subjectLocks.LoadOrStore(subject, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// commitClaim claims subject in forest root for ts, for good: the index
// entry and the grant object are each written once, and a different grant
// for a claimed log is refused whoever signed it.
func (a API) commitClaim(
	ctx context.Context,
	root logid.UUID,
	ts TransparentStatement,
	class GrantClass,
) (claimResult, error) {
	subject := ts.Grant.LogID
	defer lockSubject(subject)()

	if err := a.refuseForestRoot(ctx, root, subject); err != nil {
		return claimResult{}, err
	}
	res, held, err := a.readReservation(ctx, subject)
	if err != nil {
		return claimResult{}, err
	}
	converting := held && res.live(a.now())
	if converting {
		if err := res.checkHeldBy(root, ts.Raw); err != nil {
			return claimResult{}, err
		}
	}

	_, existing, err := a.Store.IndexCreate(ctx, subject, root)
	if err != nil {
		return claimResult{}, fmt.Errorf("index create: %w", err)
	}
	if existing != root {
		return claimResult{}, errLogInOtherForest
	}
	// The conditional put guards only its own class's key, so look for a
	// grant of either class first: a log has one create grant.
	stored, err := a.Store.GetGrant(ctx, root, subject)
	created := false
	switch {
	case err == nil:
	case errors.Is(err, massifstorage.ErrDoesNotExist):
		created, err = a.Store.PutGrantIfAbsent(ctx, root, subject, class, ts.Raw)
		if err != nil {
			return claimResult{}, err
		}
		if !created {
			stored, err = a.Store.GetGrant(ctx, root, subject)
		}
	}
	if err != nil {
		return claimResult{}, fmt.Errorf("read claimed grant: %w", err)
	}
	if !created {
		if err := requireSameGrant(stored, ts.Raw); err != nil {
			return claimResult{}, err
		}
	}
	// The committed claim supersedes any reservation; a stale one left by a
	// crash here is ignored by reads and removed by the sweep.
	if held {
		if err := a.Store.DeleteReservation(ctx, subject); err != nil {
			a.Logger.Warn("delete committed reservation failed",
				"logId", subject.String(), "error", err)
		}
	}
	return claimResult{created: created && !converting, state: stateCommitted}, nil
}

// refuseForestRoot refuses to claim another forest's root as a child in
// root: its genesis makes it the root of its own forest, whether or not its
// self-index entry has been written yet. A root's own grant is allowed.
func (a API) refuseForestRoot(ctx context.Context, root, subject logid.UUID) error {
	if subject == root {
		return nil
	}
	_, err := a.Store.GetGenesis(ctx, subject)
	switch {
	case err == nil:
		return errLogInOtherForest
	case isStoreMiss(err):
		return nil
	default:
		return fmt.Errorf("genesis lookup: %w", err)
	}
}

// requireSameGrant accepts a re-post of the claimed grant: the same grant
// content, so the same leaf once sequenced, even if signed again.
func requireSameGrant(claimed, posted []byte) error {
	want, err := publishproof.StoredGrantContentHash(claimed)
	if err != nil {
		return fmt.Errorf("claimed grant: %w", err)
	}
	got, err := publishproof.StoredGrantContentHash(posted)
	if err != nil {
		return fmt.Errorf("posted grant: %w", err)
	}
	if want != got {
		return errGrantAlreadyClaimed
	}
	return nil
}

// claim is the grant a log is claimed with, as stored.
type claim struct {
	statement []byte
	state     string // stateReserved or stateCommitted
	expiresAt time.Time
}

// errNoClaim reports a log with no committed claim and no live reservation
// in the forest asked about.
var errNoClaim = errors.New("log has no claim in this forest")

// claimedGrant returns subject's claim in forest root: the committed grant,
// else a live reservation. A lapsed reservation is absent.
//
// The reservation is read first: a commit writes the grant before it drops
// the reservation, so reading in the other order could miss both while a
// commit runs, and the sweep would take the log as unclaimed.
func (a API) claimedGrant(ctx context.Context, root, subject logid.UUID) (claim, error) {
	if a.Store == nil {
		return claim{}, ErrStoreNotConfigured
	}
	res, held, err := a.readReservation(ctx, subject)
	if err != nil {
		return claim{}, err
	}
	stmt, err := a.Store.GetGrant(ctx, root, subject)
	if err == nil {
		return claim{statement: stmt, state: stateCommitted}, nil
	}
	if !isStoreMiss(err) {
		return claim{}, fmt.Errorf("read grant: %w", err)
	}
	if !held || !res.live(a.now()) || res.root != root {
		return claim{}, fmt.Errorf("%w: %s", errNoClaim, subject)
	}
	return claim{statement: res.statement, state: stateReserved, expiresAt: res.expiresAt}, nil
}

// liveReservationRoot returns the forest a live reservation places subject
// in, for logs not yet in the committed index.
func (a API) liveReservationRoot(ctx context.Context, subject logid.UUID) (logid.UUID, bool, error) {
	res, held, err := a.readReservation(ctx, subject)
	if err != nil || !held || !res.live(a.now()) {
		return logid.Zero, false, err
	}
	return res.root, true, nil
}
