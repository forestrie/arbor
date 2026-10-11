package sealer

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

// Standing delegate key readiness (devdocs plan-2609-12 slice 05, rulings 1
// and 5): https://github.com/forestrie/devdocs/blob/main/plans/plan-2609-12-delegate-key-registration-hardening/05-sealer-readiness.md
//
// Keys are installed the moment they derive, so certificates bound to either
// epoch seal at once. Readiness and the registered gauge then follow the
// coordinator's lookup of the current key. At boot every fault (custodian
// unreachable, retired current epoch, custodian older than apiVersion 2,
// custodian 501, key unregistered) holds readiness and polls; nothing crashes.
// After boot a daily seed reload re-requests both epochs, which also
// repopulates the custodian's in-memory registration outbox after a custodian
// restart and refreshes the coordinator row's not-after. A reload never
// uninstalls or replaces keys.
const (
	delegateKeyLookupBackoffStart = time.Second
	delegateKeyLookupBackoffMax   = time.Minute
	// delegateKeyUnregisteredWarnAfter is how long the current key may stay
	// unregistered before each poll logs at warn (lanes run the sealer above
	// info, so earlier polls are silent).
	delegateKeyUnregisteredWarnAfter = 10 * time.Minute
	delegateKeyReloadInterval        = 24 * time.Hour
)

// DelegateKeyReadiness is the standing delegate key half of the sealer's
// /readyz. Ready latches: once keys are installed and the current key is
// confirmed registered it stays true for the life of the process, because
// after boot no failure removes installed keys (ruling 5); a later loss of
// registration shows on sealer_delegate_key_registered instead.
type DelegateKeyReadiness struct {
	disabled   bool
	installed  atomic.Bool
	registered atomic.Bool
}

// Ready reports whether the sealer can seal with its standing delegate keys,
// and when not, why. Always ready when delegation-in-advance is off
// (DELEGATE_KEY_EPOCH=0).
func (r *DelegateKeyReadiness) Ready() (bool, string) {
	switch {
	case r == nil || r.disabled:
		return true, ""
	case !r.installed.Load():
		return false, "standing delegate keys not loaded"
	case !r.registered.Load():
		return false, "current delegate key not registered on every coordinator shard"
	default:
		return true, ""
	}
}

// DelegateKeyRegisteredGauge sets sealer_delegate_key_registered; satisfied by
// *metrics.Metrics, and an interface so tests can observe it.
type DelegateKeyRegisteredGauge interface {
	SetDelegateKeyRegistered(epoch uint32, registered bool)
}

// delegateKeyRunner owns the standing delegate key lifecycle after the first
// boot attempt: boot load retry, install, registration poll, daily reload.
// The function fields are seams for tests.
type delegateKeyRunner struct {
	logger    *slog.Logger
	epoch     uint32
	readiness *DelegateKeyReadiness
	gauge     DelegateKeyRegisteredGauge

	load    func(context.Context) (*DelegateKeySet, error)
	install func(*DelegateKeySet)
	// lookup is nil when no custodian registration exists to observe (the
	// test-only local seed); the current key then counts as registered.
	lookup func(ctx context.Context, pubkeyHash string) (registered bool, detail string, err error)

	loadBackoffStart, loadBackoffMax     time.Duration
	lookupBackoffStart, lookupBackoffMax time.Duration
	warnAfter                            time.Duration
	reloadInterval                       time.Duration
	now                                  func() time.Time
}

// run drives the lifecycle until ctx ends. keys is the result of the inline
// first boot attempt, or nil when that failed and the load must be retried.
func (r *delegateKeyRunner) run(ctx context.Context, keys *DelegateKeySet) {
	if keys == nil {
		if keys = r.loadWithRetry(ctx); keys == nil {
			return
		}
		r.installKeys(keys)
	}
	currentHash, err := pubkeyHashHex(&keys.Current().PublicKey)
	if err != nil {
		// Unreachable for a key LoadDelegateKeys derived; hold readiness.
		r.logger.Error("hash current delegate key; holding readiness", "epoch", r.epoch, "error", err)
		return
	}
	if r.lookup == nil {
		r.readiness.registered.Store(true)
		r.logger.Warn("delegation-in-advance enabled (local seed; no coordinator registration to confirm)",
			"delegate_key_epoch", r.epoch)
		return
	}

	reload := time.NewTicker(r.reloadInterval)
	defer reload.Stop()
	poll := time.NewTimer(0)
	defer poll.Stop()
	pendingSince := r.now()
	backoff := r.lookupBackoffStart
	for {
		select {
		case <-ctx.Done():
			return
		case <-reload.C:
			r.reload(ctx, keys)
			// Re-confirm after every reload, success or failure: the gauge
			// drops to 0 only when the lookup also fails.
			pendingSince = r.now()
			backoff = r.lookupBackoffStart
			poll.Reset(0)
		case <-poll.C:
			if !r.checkRegistered(ctx, currentHash, pendingSince) {
				poll.Reset(backoff)
				backoff = min(backoff*2, r.lookupBackoffMax)
			}
		}
	}
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
		keys, err := r.load(ctx)
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
	r.logger.Warn(msg, "epoch", r.epoch, "error", err)
}

func (r *delegateKeyRunner) installKeys(keys *DelegateKeySet) {
	r.install(keys)
	r.readiness.installed.Store(true)
	r.logger.Warn("standing delegate keys installed; confirming registration", "delegate_key_epoch", r.epoch)
}

// checkRegistered runs one lookup for the current key and applies it to the
// gauge and readiness. A 404 sets the gauge to 0; an error leaves the gauge
// as it was, since registration is then unknown rather than absent.
func (r *delegateKeyRunner) checkRegistered(ctx context.Context, currentHash string, pendingSince time.Time) bool {
	ok, detail, err := r.lookup(ctx, currentHash)
	if ok {
		r.gauge.SetDelegateKeyRegistered(r.epoch, true)
		if !r.readiness.registered.Swap(true) {
			r.logger.Warn("delegation-in-advance enabled", "delegate_key_epoch", r.epoch, "pubkeyHash", currentHash)
		} else {
			r.logger.Info("delegate key registration confirmed", "delegate_key_epoch", r.epoch, "pubkeyHash", currentHash)
		}
		return true
	}
	if err == nil {
		r.gauge.SetDelegateKeyRegistered(r.epoch, false)
	}
	attrs := []any{"delegate_key_epoch", r.epoch, "pubkeyHash", currentHash,
		"pendingFor", r.now().Sub(pendingSince).Round(time.Second).String()}
	if err != nil {
		attrs = append(attrs, "error", err)
	} else {
		attrs = append(attrs, "detail", detail)
	}
	if r.now().Sub(pendingSince) >= r.warnAfter {
		r.logger.Warn("current delegate key not registered on every coordinator shard; still polling", attrs...)
	} else {
		r.logger.Info("current delegate key not yet registered; polling", attrs...)
	}
	return false
}

// reload re-requests the seeds for the installed epochs. The installed set is
// never changed (ruling 5): a failure is logged and the keys stay; a success
// that derives the same keys is a no-op; keys the installed set does not hold
// (the MAC key changed under the epoch) are refused until a restart adopts
// them, and a smaller set (epoch N-1 retired since boot) keeps N-1 installed.
func (r *delegateKeyRunner) reload(ctx context.Context, installed *DelegateKeySet) {
	fresh, err := r.load(ctx)
	if err != nil {
		r.logger.Warn("delegate key reload failed; keeping installed keys", "delegate_key_epoch", r.epoch, "error", err)
		return
	}
	held := make(map[string]bool, len(installed.byPubkeyHash))
	for h := range installed.byPubkeyHash {
		held[h] = true
	}
	for h := range fresh.byPubkeyHash {
		if !held[h] {
			r.logger.Error("reloaded delegate key is not in the installed set; keeping installed keys (a restart adopts it)",
				"delegate_key_epoch", r.epoch, "pubkeyHash", h)
			return
		}
	}
	r.logger.Info("delegate keys reloaded; installed set unchanged",
		"delegate_key_epoch", r.epoch, "installed", len(held), "reloaded", len(fresh.byPubkeyHash))
}
