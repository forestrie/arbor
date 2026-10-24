package sealer

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"
)

// The standing delegate key lifecycle (devdocs plan-2609-12 slice 05,
// rulings 1′, 4′, 5 and 7):
// https://github.com/forestrie/devdocs/blob/main/plans/plan-2609-12-delegate-key-registration-hardening/05-sealer-readiness.md
//
// Keys install the moment they derive. The sealer then asserts each held key
// with the coordinator every minute, presenting the custodian's voucher, and
// is Ready once the current key's first assertion succeeds. Vouchers are
// re-requested from the custodian at a quarter of their lifetime. At boot
// every fault holds readiness and retries; after boot nothing changes the
// installed key set.
const (
	delegateSeedRetryBackoffStart = time.Second
	delegateSeedRetryBackoffMax   = 30 * time.Second
	delegateKeyAssertInterval     = 60 * time.Second
	delegateKeyAssertJitter       = 10 * time.Second
	delegateKeyAssertBackoffStart = time.Second
	delegateKeyAssertBackoffMax   = 60 * time.Second
	delegateKeyRegisteredFor      = 5 * time.Minute
	delegateKeyWarnLogInterval    = 10 * time.Minute
)

// voucherRefreshAfter is when to re-request seeds after a voucher with this
// lifetime arrived: a quarter of it (6 h at the custodian's 24 h default).
func voucherRefreshAfter(lifetime time.Duration) time.Duration { return lifetime / 4 }

// voucherRefreshRetryAfter is the retry after a failed refresh: a
// twenty-fourth of the lifetime (1 h at the default).
func voucherRefreshRetryAfter(lifetime time.Duration) time.Duration { return lifetime / 24 }

// DelegateKeyRegisteredGauge sets sealer_delegate_key_registered; satisfied
// by *metrics.Metrics. A retired key's series is deleted rather than left at
// 0, so the end of a rotation overlap never pages.
type DelegateKeyRegisteredGauge interface {
	SetDelegateKeyRegistered(epoch uint32, registered bool)
	DeleteDelegateKeyRegistered(epoch uint32)
}

// heldVoucher is the voucher in use for one installed epoch.
type heldVoucher struct {
	v          *DelegateKeyVoucher
	receivedAt time.Time
}

// delegateKeyRunner owns the lifecycle. The function and timing fields are
// seams for tests; newDelegateKeyRunner sets the production values.
type delegateKeyRunner struct {
	logger    *slog.Logger
	sealerID  string
	epoch     uint32
	readiness *DelegateKeyReadiness
	gauge     DelegateKeyRegisteredGauge

	load    func(context.Context) (*DelegateKeySet, error)
	install func(*DelegateKeySet)
	// assert is nil when the seed provider is not the custodian (the
	// test-only local seed): there is no voucher, so nothing to assert.
	assert func(ctx context.Context, sealerID string, key registerDelegateKeyEntry) assertResult

	loadBackoffStart, loadBackoffMax     time.Duration
	assertInterval, assertJitter         time.Duration
	assertBackoffStart, assertBackoffMax time.Duration
	registeredFor                        time.Duration
	warnLogEvery                         time.Duration // per key and outcome
	refreshAfter, refreshRetryAfter      func(lifetime time.Duration) time.Duration
	now                                  func() time.Time

	wg         sync.WaitGroup
	refreshNow chan struct{}
	mu         sync.Mutex
	vouchers   map[uint32]heldVoucher
	// retired holds epochs that are no longer asserted or refreshed: the
	// custodian retired N-1 after boot, or the coordinator answered 410.
	retired map[uint32]bool
}

// start makes the first load inline, so a healthy seed source installs keys
// before it returns, and runs the rest of the lifecycle in the background.
func (r *delegateKeyRunner) start(ctx context.Context) {
	r.refreshNow = make(chan struct{}, 1)
	if r.assert != nil {
		// Export 0 from boot so "registered == 0 for 15 min" also catches a
		// sealer that never installs its keys.
		r.setGauge(r.epoch, false)
	}
	keys, err := r.loadOnce(ctx)
	if err != nil {
		r.logLoadFailure(err)
	} else {
		r.installKeys(keys)
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.run(ctx, keys)
	}()
}

// wait blocks until every lifecycle goroutine has exited (after ctx ends).
func (r *delegateKeyRunner) wait() { r.wg.Wait() }

func (r *delegateKeyRunner) run(ctx context.Context, keys *DelegateKeySet) {
	if keys == nil {
		if keys = r.loadWithRetry(ctx); keys == nil {
			return
		}
		r.installKeys(keys)
	}
	if r.assert == nil {
		return
	}
	received := r.now()
	r.mu.Lock()
	r.vouchers = map[uint32]heldVoucher{}
	for _, e := range keys.entries {
		if r.usableVoucher(e, received) {
			r.vouchers[e.epoch] = heldVoucher{v: e.voucher, receivedAt: received}
		}
	}
	r.mu.Unlock()
	for _, e := range keys.entries {
		r.setGauge(e.epoch, false)
		r.wg.Add(1)
		go func(e delegateKeyEntry) {
			defer r.wg.Done()
			r.assertLoop(ctx, e, e.epoch == r.epoch)
		}(e)
	}
	r.refreshLoop(ctx, keys)
}

func (r *delegateKeyRunner) loadOnce(ctx context.Context) (*DelegateKeySet, error) {
	keys, err := r.load(ctx)
	if err == nil && keys == nil {
		err = errors.New("delegate key load returned no keys")
	}
	return keys, err
}

// loadWithRetry retries the boot load with backoff until it succeeds or ctx
// ends (nil). Every fault holds readiness; none is fatal.
func (r *delegateKeyRunner) loadWithRetry(ctx context.Context) *DelegateKeySet {
	backoff := r.loadBackoffStart
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		keys, err := r.loadOnce(ctx)
		if err == nil {
			return keys
		}
		r.logLoadFailure(err)
		backoff = min(backoff*2, r.loadBackoffMax)
	}
}

func (r *delegateKeyRunner) logLoadFailure(err error) {
	msg := "delegate key schedule not ready (holding readiness, will retry)"
	if errors.Is(err, errDelegateSeedEpochRetired) {
		// The sealer was bumped to an epoch whose MAC key version does not
		// exist or is disabled: the previous pod keeps serving the rollout.
		msg = "current delegate epoch retired by the custodian (holding readiness, will retry)"
	}
	r.logger.Warn(msg, "delegate_key_epoch", r.epoch, "error", err)
}

func (r *delegateKeyRunner) installKeys(keys *DelegateKeySet) {
	r.install(keys)
	r.readiness.markInstalled()
	current := ""
	if len(keys.entries) > 0 {
		current = keys.entries[0].pubkeyHash
	}
	if r.assert == nil {
		// The local seed has no voucher and no registration: Ready now.
		r.readiness.markReady()
		r.logger.Warn("delegation-in-advance enabled (local seed; no registration to assert)",
			"delegate_key_epoch", r.epoch, "keys", len(keys.entries), "currentPubkeyHash", current)
		return
	}
	r.logger.Warn("standing delegate keys installed; asserting registration",
		"delegate_key_epoch", r.epoch, "keys", len(keys.entries), "currentPubkeyHash", current)
}

// usableVoucher reports whether e carries a voucher that is still valid.
func (r *delegateKeyRunner) usableVoucher(e delegateKeyEntry, now time.Time) bool {
	if e.voucher == nil {
		return false
	}
	if !e.voucher.NotAfter.After(now) {
		r.logger.Warn("custodian returned an expired delegate key voucher; ignoring it",
			"epoch", e.epoch, "voucherNotAfter", e.voucher.NotAfter)
		return false
	}
	return true
}

// setGauge sets an epoch's series unless the epoch is retired, so a late
// write can never re-create a deleted series.
func (r *delegateKeyRunner) setGauge(epoch uint32, registered bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.gauge != nil && !r.retired[epoch] {
		r.gauge.SetDelegateKeyRegistered(epoch, registered)
	}
}

// retire stops asserting and refreshing epoch and deletes its gauge series.
// It reports false when epoch was already retired.
func (r *delegateKeyRunner) retire(epoch uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired == nil {
		r.retired = map[uint32]bool{}
	}
	if r.retired[epoch] {
		return false
	}
	r.retired[epoch] = true
	if r.gauge != nil {
		r.gauge.DeleteDelegateKeyRegistered(epoch)
	}
	return true
}

func (r *delegateKeyRunner) isRetired(epoch uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.retired[epoch]
}

// throttle reports whether a warn for this key and outcome is due: the
// first one, then one per warnLogEvery. *at is that outcome's last warn.
func (r *delegateKeyRunner) throttle(at *time.Time, now time.Time) bool {
	if at.IsZero() || now.Sub(*at) >= r.warnLogEvery {
		*at = now
		return true
	}
	return false
}

func (r *delegateKeyRunner) voucherFor(epoch uint32) (heldVoucher, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	hv, ok := r.vouchers[epoch]
	return hv, ok
}

func (r *delegateKeyRunner) requestRefresh() {
	select {
	case r.refreshNow <- struct{}{}:
	default:
	}
}

func (r *delegateKeyRunner) nextInterval() time.Duration {
	if r.assertJitter <= 0 {
		return r.assertInterval
	}
	return r.assertInterval - r.assertJitter + rand.N(2*r.assertJitter+1)
}

// assertLoop asserts one held key until ctx ends or the key is retired (a
// coordinator 410, or the custodian retiring N-1 after boot). The current
// key's first success makes the sealer Ready.
func (r *delegateKeyRunner) assertLoop(ctx context.Context, e delegateKeyEntry, current bool) {
	backoff := r.assertBackoffStart
	grow := func() time.Duration {
		d := backoff
		backoff = min(backoff*2, r.assertBackoffMax)
		return d
	}
	var lastOK time.Time
	// Last warn per outcome: the first, then one per warnLogEvery.
	var conflictWarned, voucherWarned, retryWarned time.Time
	expiredLogged := false
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if r.isRetired(e.epoch) {
			return
		}
		hv, ok := r.voucherFor(e.epoch)
		if now := r.now(); !ok || !hv.v.NotAfter.After(now) {
			// No voucher yet, or it expired unrefreshed: nothing to assert
			// with. The refresh loop fetches one; check again shortly.
			r.setGauge(e.epoch, false)
			lastOK = time.Time{}
			if ok && !expiredLogged {
				r.logger.Error("delegate key voucher expired unrefreshed; not asserting this key until a refresh succeeds",
					"epoch", e.epoch, "pubkeyHash", e.pubkeyHash, "voucherNotAfter", hv.v.NotAfter)
				expiredLogged = true
			}
			timer.Reset(grow())
			continue
		}
		expiredLogged = false
		res := r.assert(ctx, r.sealerID, registerDelegateKeyEntry{
			Alg:       "ES256",
			PublicKey: base64.StdEncoding.EncodeToString(e.coseKey),
			Epoch:     e.epoch,
			NotAfter:  hv.v.NotAfter.Unix(),
			Voucher:   base64.StdEncoding.EncodeToString(hv.v.Raw),
		})
		now := r.now()
		attrs := []any{"epoch", e.epoch, "pubkeyHash", e.pubkeyHash, "status", res.status, "detail", res.detail}
		r.logger.Debug("delegate key assertion attempt", append(attrs, "outcome", res.kind.String(), "error", res.err)...)
		var wait time.Duration
		switch res.kind {
		case assertOK:
			lastOK = now
			conflictWarned, voucherWarned, retryWarned = time.Time{}, time.Time{}, time.Time{}
			r.setGauge(e.epoch, true)
			backoff = r.assertBackoffStart
			if current && !r.readiness.Ready() {
				r.readiness.markReady()
				r.logger.Warn("delegation-in-advance enabled", "delegate_key_epoch", r.epoch, "pubkeyHash", e.pubkeyHash)
			}
			wait = r.nextInterval()
		case assertConflict:
			lastOK = time.Time{}
			r.setGauge(e.epoch, false)
			if r.throttle(&conflictWarned, now) {
				r.logger.Error("delegate key registration conflict: another key holds this sealer and epoch (still asserting; deleting the stale row heals it)", attrs...)
			}
			wait = r.nextInterval()
		case assertTombstoned:
			if r.retire(e.epoch) {
				r.logger.Error("delegate key tombstoned by the coordinator; no longer asserting it", attrs...)
			}
			return
		case assertVoucherRefused:
			lastOK = time.Time{}
			r.setGauge(e.epoch, false)
			if r.throttle(&voucherWarned, now) {
				r.logger.Warn("coordinator refused the delegate key voucher; refreshing vouchers", attrs...)
			}
			r.requestRefresh()
			wait = grow()
		default:
			r.setGauge(e.epoch, !lastOK.IsZero() && now.Sub(lastOK) < r.registeredFor)
			if r.throttle(&retryWarned, now) {
				r.logger.Warn("delegate key assertion failed (will retry)", append(attrs, "error", res.err)...)
			}
			wait = grow()
		}
		timer.Reset(wait)
	}
}

// refreshLoop re-requests both epochs' seeds to renew their vouchers, timed
// from the vouchers themselves; the custodian's DELEGATE_KEY_VOUCHER_TTL is
// the only knob.
func (r *delegateKeyRunner) refreshLoop(ctx context.Context, installed *DelegateKeySet) {
	renewed := true
	missingBackoff := r.assertBackoffStart
	for {
		delay, missing, stop := r.planRefresh(installed, renewed)
		if stop {
			return // every held key is retired
		}
		if missing {
			// A held key has never had a voucher (the custodian answered
			// without one): ask again at the assertion backoff.
			delay = missingBackoff
			missingBackoff = min(missingBackoff*2, r.assertBackoffMax)
		} else {
			missingBackoff = r.assertBackoffStart
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-r.refreshNow:
			timer.Stop()
		}
		fresh, err := r.loadOnce(ctx)
		renewed = r.applyRefresh(installed, fresh, err)
	}
}

// planRefresh returns the delay to the next refresh, ignoring retired keys.
// missing reports a held key that has no voucher at all; stop, that every
// held key is retired.
func (r *delegateKeyRunner) planRefresh(installed *DelegateKeySet, renewed bool) (delay time.Duration, missing, stop bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var minLife time.Duration
	var earliest time.Time
	live := 0
	for _, e := range installed.entries {
		if r.retired[e.epoch] {
			continue
		}
		live++
		hv, ok := r.vouchers[e.epoch]
		if !ok {
			missing = true
			continue
		}
		life := hv.v.NotAfter.Sub(hv.receivedAt)
		if minLife == 0 || life < minLife {
			minLife = life
		}
		if at := hv.receivedAt.Add(r.refreshAfter(life)); earliest.IsZero() || at.Before(earliest) {
			earliest = at
		}
	}
	if live == 0 {
		return 0, false, true
	}
	if missing {
		return 0, true, false
	}
	delay = earliest.Sub(now)
	if !renewed || delay <= 0 {
		delay = r.refreshRetryAfter(minLife)
	}
	return max(delay, r.assertBackoffStart), false, false
}

// applyRefresh adopts the reloaded vouchers and reports whether every held
// epoch got a fresh one. The installed key set never changes (ruling 5): a
// failed reload keeps keys and vouchers; a reload deriving a different key
// for an installed epoch is refused until a restart adopts it; an epoch
// absent at boot (N-1 re-enabled) installs nothing. N-1 retired by the
// custodian since boot is retired here too: the key stays installed for
// certificates bound to it, but is no longer asserted, refreshed or
// exported.
func (r *delegateKeyRunner) applyRefresh(installed, fresh *DelegateKeySet, err error) bool {
	if err != nil {
		r.logger.Warn("delegate voucher refresh failed; keeping installed keys and vouchers",
			"delegate_key_epoch", r.epoch, "error", err)
		return false
	}
	if fresh.PreviousRetired() {
		for _, e := range installed.entries {
			if e.epoch == r.epoch-1 && r.retire(e.epoch) {
				r.logger.Warn("previous delegate epoch retired by the custodian; no longer asserting it",
					"epoch", e.epoch, "pubkeyHash", e.pubkeyHash)
			}
		}
	}
	now := r.now()
	held := make(map[uint32]delegateKeyEntry, len(installed.entries))
	for _, e := range installed.entries {
		held[e.epoch] = e
	}
	renewed := map[uint32]bool{}
	for _, f := range fresh.entries {
		h, ok := held[f.epoch]
		switch {
		case !ok:
			r.logger.Info("delegate key epoch absent at boot is derivable again; installing nothing until a restart adopts it",
				"epoch", f.epoch, "pubkeyHash", f.pubkeyHash)
		case f.pubkeyHash != h.pubkeyHash:
			r.logger.Error("reloaded delegate key differs from the installed key; refusing it until a restart adopts it",
				"epoch", f.epoch, "installedPubkeyHash", h.pubkeyHash, "reloadedPubkeyHash", f.pubkeyHash)
		case r.usableVoucher(f, now):
			r.mu.Lock()
			r.vouchers[f.epoch] = heldVoucher{v: f.voucher, receivedAt: now}
			r.mu.Unlock()
			renewed[f.epoch] = true
		}
	}
	all := true
	for epoch := range held {
		if !renewed[epoch] && !r.isRetired(epoch) {
			all = false
		}
	}
	if all {
		r.logger.Info("delegate vouchers refreshed", "delegate_key_epoch", r.epoch, "keys", len(renewed))
	}
	return all
}
