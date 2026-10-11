package custodian

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegatekeys"
)

// Registration outbox bounds (plan-2609-12 slice 03, ruling 1).
const (
	// registrationOutboxCap bounds the entries held. Entries exist only for
	// (allowlisted sealer, existing key version) pairs, so 64 is generous;
	// overflow is a bug or a misconfiguration and is logged at error.
	registrationOutboxCap = 64
	// registrationBackoffBase is the first retry interval; it doubles per
	// failed attempt up to registrationBackoffMax.
	registrationBackoffBase = 2 * time.Second
	// registrationBackoffMax caps the retry INTERVAL. Attempts are never
	// capped: an entry is retried until it lands or is refused with 409.
	registrationBackoffMax = 5 * time.Minute
	// registrationAttemptTimeout is the custodian's own deadline for one
	// attempt (voucher signing plus the coordinator POST). It is independent
	// of the sealer's seed request, which has already been answered.
	registrationAttemptTimeout = 30 * time.Second
)

// registrationKey identifies an outbox entry. A sealer has at most one
// standing key per epoch (the coordinator enforces it, slice 04), so a repeat
// seed request for the same pair upserts rather than queues.
type registrationKey struct {
	sealerID string
	epoch    uint32
}

// registrationEntry is one pending registration. Nothing in it is secret: it
// holds exactly what the coordinator receives (public key, voucher), never the
// seed.
type registrationEntry struct {
	sealerID      string
	epoch         uint32
	kmsKeyVersion string
	publicKey     *ecdsa.PublicKey
	coseKey       []byte // canonical COSE_Key CBOR
	pubkeyHash    string // hex(sha256(coseKey)), the coordinator's key id
	// voucher is signed once per entry on its first attempt; its claims carry
	// no expiry, so it stays valid across retries.
	voucher     []byte
	attempts    int
	nextAttempt time.Time
}

// registrationOutcome is the coordinator's answer to one attempt. err is set
// when no HTTP status was obtained (transport failure, voucher signing).
type registrationOutcome struct {
	status int
	body   []byte
	err    error
}

// coordinatorConflict is the slice-04 409 body: the coordinator already holds
// a different unexpired key for (sealerId, epoch).
type coordinatorConflict struct {
	Detail             string `json:"detail"`
	SealerID           string `json:"sealerId"`
	Epoch              uint32 `json:"epoch"`
	PubkeyHash         string `json:"pubkeyHash"`
	ExistingPubkeyHash string `json:"existingPubkeyHash"`
}

// registrationOutbox registers standing delegate keys with the coordinator
// off the seed request's path: one worker goroutine, one request in flight,
// exponential backoff capped on the interval, never on the attempts. A 2xx
// removes the entry; a 409 is terminal and removes it without retrying. The
// outbox is in memory: a custodian restart loses it and the sealer's daily
// seed reload (slice 05) repopulates it.
type registrationOutbox struct {
	logger *slog.Logger
	now    func() time.Time
	ttl    time.Duration
	// backoffBase and backoffMax bound the retry interval (tests shrink them).
	backoffBase time.Duration
	backoffMax  time.Duration
	// signVoucher signs the registrar voucher for an entry's claims.
	signVoucher func(ctx context.Context, claims DelegateKeyVoucherClaims) ([]byte, error)
	// post sends one registration body to the coordinator.
	post func(ctx context.Context, body RegisterDelegateKeysBody) registrationOutcome

	mu      sync.Mutex
	entries map[registrationKey]*registrationEntry
	wake    chan struct{}
}

func newRegistrationOutbox(
	logger *slog.Logger,
	signVoucher func(context.Context, DelegateKeyVoucherClaims) ([]byte, error),
	post func(context.Context, RegisterDelegateKeysBody) registrationOutcome,
) *registrationOutbox {
	return &registrationOutbox{
		logger:      logger,
		now:         time.Now,
		ttl:         defaultDelegateKeyTTL,
		backoffBase: registrationBackoffBase,
		backoffMax:  registrationBackoffMax,
		signVoucher: signVoucher,
		post:        post,
		entries:     make(map[registrationKey]*registrationEntry),
		wake:        make(chan struct{}, 1),
	}
}

// enqueue derives the standing public key for (sealerID, epoch) from seed and
// upserts an outbox entry for it, due immediately. The seed is not retained.
// A repeat request for a pending pair with the same key keeps its voucher; a
// different key (the MAC key changed underneath the epoch) replaces the entry.
// Never blocks on the network.
func (o *registrationOutbox) enqueue(sealerID string, epoch uint32, kmsKeyVersion string, seed []byte) error {
	priv, err := delegatekeys.DeriveKey(seed, epoch, 0)
	if err != nil {
		return fmt.Errorf("derive delegate key: %w", err)
	}
	pub := &priv.PublicKey
	coseKey, err := delegatekeys.CoseKeyBytes(pub)
	if err != nil {
		return fmt.Errorf("encode delegate key: %w", err)
	}
	pubkeyHash, err := delegatekeys.PubkeyHashHex(pub)
	if err != nil {
		return fmt.Errorf("hash delegate key: %w", err)
	}

	k := registrationKey{sealerID: sealerID, epoch: epoch}
	o.mu.Lock()
	e, ok := o.entries[k]
	switch {
	case ok && e.pubkeyHash == pubkeyHash:
		// Dedupe: a repeat seed request is a fresh signal the sealer wants
		// the key registered, so make the entry due now.
		e.kmsKeyVersion = kmsKeyVersion
		e.nextAttempt = o.now()
	case !ok && len(o.entries) >= registrationOutboxCap:
		o.mu.Unlock()
		o.logger.Error("delegate key registration outbox full; dropping entry",
			"sealerId", sealerID, "epoch", epoch, "kmsKeyVersion", kmsKeyVersion,
			"pubkeyHash", pubkeyHash, "cap", registrationOutboxCap)
		return fmt.Errorf("registration outbox full (%d entries)", registrationOutboxCap)
	default:
		if ok {
			o.logger.Warn("delegate key registration replaced: key changed for epoch",
				"sealerId", sealerID, "epoch", epoch,
				"pubkeyHash", pubkeyHash, "replacedPubkeyHash", e.pubkeyHash)
		}
		o.entries[k] = &registrationEntry{
			sealerID:      sealerID,
			epoch:         epoch,
			kmsKeyVersion: kmsKeyVersion,
			publicKey:     pub,
			coseKey:       coseKey,
			pubkeyHash:    pubkeyHash,
			nextAttempt:   o.now(),
		}
	}
	o.mu.Unlock()
	o.signal()
	return nil
}

func (o *registrationOutbox) signal() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// len reports the number of pending entries.
func (o *registrationOutbox) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.entries)
}

// next returns the entry due soonest, or nil when the outbox is empty.
func (o *registrationOutbox) next() *registrationEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	var due *registrationEntry
	for _, e := range o.entries {
		if due == nil || e.nextAttempt.Before(due.nextAttempt) {
			due = e
		}
	}
	return due
}

// run is the single worker. It attempts the entry due soonest, one request at
// a time, and sleeps until the next one is due or an enqueue wakes it.
func (o *registrationOutbox) run(ctx context.Context) {
	for {
		var wait <-chan time.Time
		if e := o.next(); e != nil {
			if d := e.nextAttempt.Sub(o.now()); d > 0 {
				timer := time.NewTimer(d)
				wait = timer.C
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-o.wake:
					timer.Stop()
					continue
				case <-wait:
				}
			}
			o.attempt(ctx, e)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-o.wake:
		}
	}
}

// attempt makes one registration attempt for e and applies its outcome.
func (o *registrationOutbox) attempt(ctx context.Context, e *registrationEntry) {
	attemptCtx, cancel := context.WithTimeout(ctx, registrationAttemptTimeout)
	defer cancel()

	k := registrationKey{sealerID: e.sealerID, epoch: e.epoch}
	o.mu.Lock()
	if o.entries[k] != e {
		// Replaced by an upsert with a different key since it was picked.
		o.mu.Unlock()
		return
	}
	voucher := e.voucher
	kmsKeyVersion := e.kmsKeyVersion
	e.attempts++
	attempts := e.attempts
	o.mu.Unlock()

	var outcome registrationOutcome
	if voucher == nil {
		v, err := o.signVoucher(attemptCtx, DelegateKeyVoucherClaims{SealerID: e.sealerID, Epoch: e.epoch, PublicKey: e.publicKey})
		if err != nil {
			outcome.err = fmt.Errorf("sign voucher: %w", err)
		} else {
			voucher = v
			o.mu.Lock()
			e.voucher = v
			o.mu.Unlock()
		}
	}
	if outcome.err == nil {
		// The not-after is rebuilt per attempt so a long retry does not
		// shorten the registered key's life.
		outcome = o.post(attemptCtx, RegisterDelegateKeysBody{
			SealerID: e.sealerID,
			Keys: []RegisterDelegateKeyEntry{{
				Alg:       "ES256",
				PublicKey: base64.StdEncoding.EncodeToString(e.coseKey),
				Epoch:     e.epoch,
				NotAfter:  o.now().Add(o.ttl).Unix(),
				Voucher:   base64.StdEncoding.EncodeToString(voucher),
			}},
		})
	}

	attrs := []any{
		"sealerId", e.sealerID, "epoch", e.epoch, "kmsKeyVersion", kmsKeyVersion,
		"pubkeyHash", e.pubkeyHash, "attempt", attempts,
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	current, stillPending := o.entries[k]
	switch {
	case outcome.err == nil && outcome.status >= 200 && outcome.status < 300:
		if stillPending && current == e {
			delete(o.entries, k)
		}
		o.logger.Info("delegate key registration attempt", append(attrs, "outcome", "registered", "status", outcome.status)...)
	case outcome.err == nil && outcome.status == http.StatusConflict:
		// Terminal (slice 04's one key per (sealer, epoch)): the coordinator
		// holds a different unexpired key for this epoch. Retrying cannot
		// turn this into success, so the entry is dropped and the sealer's
		// registered gauge stays at zero.
		if stillPending && current == e {
			delete(o.entries, k)
		}
		var c coordinatorConflict
		_ = json.Unmarshal(outcome.body, &c)
		o.logger.Error("delegate key registration attempt", append(attrs,
			"outcome", "conflict", "status", outcome.status,
			"existingPubkeyHash", c.ExistingPubkeyHash, "refusedPubkeyHash", c.PubkeyHash,
			"detail", c.Detail)...)
	default:
		backoff := o.backoff(attempts)
		if stillPending && current == e {
			e.nextAttempt = o.now().Add(backoff)
		}
		reason := ""
		if outcome.err != nil {
			reason = outcome.err.Error()
		} else {
			reason = string(outcome.body)
		}
		o.logger.Info("delegate key registration attempt", append(attrs,
			"outcome", "retry", "status", outcome.status, "error", reason, "retryIn", backoff.String())...)
	}
}

// backoff is the interval after the given number of failed attempts: base
// doubling per attempt, capped at backoffMax. The attempt count itself is
// never capped.
func (o *registrationOutbox) backoff(attempts int) time.Duration {
	d := o.backoffBase
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= o.backoffMax {
			return o.backoffMax
		}
	}
	return d
}
