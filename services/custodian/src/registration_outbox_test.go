package custodian

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegatekeys"
	"github.com/stretchr/testify/require"
)

// syncBuffer is a goroutine-safe log sink for asserting on outbox log lines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// testSeed returns a distinct 32-byte seed per n.
func testSeed(n byte) []byte {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i) + n
	}
	return seed
}

// testOutbox builds an outbox with a real voucher signer (an in-memory
// registrar key) and the given post fake; it returns the log sink and a
// counter of voucher signatures.
func testOutbox(t *testing.T, post func(context.Context, RegisterDelegateKeysBody) registrationOutcome) (*registrationOutbox, *syncBuffer, *atomic.Int32) {
	t.Helper()
	_, signer, kid := registrarKey(t)
	var signs atomic.Int32
	logs := &syncBuffer{}
	o := newRegistrationOutbox(
		slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		func(_ context.Context, c DelegateKeyVoucherClaims) ([]byte, error) {
			signs.Add(1)
			return BuildDelegateKeyVoucherWithSigner(c, kid, signer)
		},
		post,
	)
	o.backoffBase = time.Millisecond
	o.backoffMax = 4 * time.Millisecond
	return o, logs, &signs
}

func ok200(context.Context, RegisterDelegateKeysBody) registrationOutcome {
	return registrationOutcome{status: http.StatusOK, body: []byte(`{"registered":1,"retired":0,"shards":4}`)}
}

// TestOutbox_BodyBindsDerivedKeyAndVoucher: the registration carries the
// standing key derived from the seed (canonical COSE_Key, the coordinator's
// pubkey_hash preimage), a voucher that verifies against the registrar key
// for it, and a not-after rebuilt from the attempt time; a 2xx removes the
// entry.
func TestOutbox_BodyBindsDerivedKeyAndVoucher(t *testing.T) {
	reg, signer, kid := registrarKey(t)
	var got RegisterDelegateKeysBody
	o := newRegistrationOutbox(slog.Default(),
		func(_ context.Context, c DelegateKeyVoucherClaims) ([]byte, error) {
			return BuildDelegateKeyVoucherWithSigner(c, kid, signer)
		},
		func(_ context.Context, body RegisterDelegateKeysBody) registrationOutcome {
			got = body
			return registrationOutcome{status: http.StatusOK}
		})
	now := time.Unix(1_800_000_000, 0)
	o.now = func() time.Time { return now }

	seed := testSeed(0)
	require.NoError(t, o.enqueue("sealer-a", 3, "k/cryptoKeyVersions/3", seed))
	o.attempt(context.Background(), o.next())
	require.Equal(t, 0, o.len(), "2xx removes the entry")

	require.Equal(t, "sealer-a", got.SealerID)
	require.Len(t, got.Keys, 1)
	entry := got.Keys[0]
	require.Equal(t, "ES256", entry.Alg)
	require.Equal(t, uint32(3), entry.Epoch)
	require.Equal(t, now.Add(defaultDelegateKeyTTL).Unix(), entry.NotAfter)

	priv, err := delegatekeys.DeriveKey(seed, 3, 0)
	require.NoError(t, err)
	wantCose, err := delegatekeys.CoseKeyBytes(&priv.PublicKey)
	require.NoError(t, err)
	gotCose, err := base64.StdEncoding.DecodeString(entry.PublicKey)
	require.NoError(t, err)
	require.Equal(t, wantCose, gotCose)

	voucher, err := base64.StdEncoding.DecodeString(entry.Voucher)
	require.NoError(t, err)
	require.NoError(t, VerifyDelegateKeyVoucher(voucher, &reg.PublicKey,
		DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: &priv.PublicKey}))
}

// TestOutbox_RetriesUntil2xx: transport errors and non-409 statuses are
// retried by the worker until a 2xx lands; the voucher is signed once and the
// not-after is rebuilt per attempt.
func TestOutbox_RetriesUntil2xx(t *testing.T) {
	var calls atomic.Int32
	var mu sync.Mutex
	var notAfters []int64
	outcomes := []registrationOutcome{
		{err: errors.New("dial tcp: connection refused")},
		{status: http.StatusServiceUnavailable, body: []byte("PINNED_REGISTRAR_KEY is not configured")},
		{status: http.StatusInternalServerError},
		{status: http.StatusOK},
	}
	o, logs, signs := testOutbox(t, func(_ context.Context, body RegisterDelegateKeysBody) registrationOutcome {
		n := calls.Add(1)
		mu.Lock()
		notAfters = append(notAfters, body.Keys[0].NotAfter)
		mu.Unlock()
		return outcomes[min(int(n), len(outcomes))-1]
	})
	var tick atomic.Int64
	o.now = func() time.Time { return time.Unix(1_800_000_000+tick.Add(1), 0) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go o.run(ctx)
	require.NoError(t, o.enqueue("sealer-a", 1, "k/cryptoKeyVersions/1", testSeed(0)))

	require.Eventually(t, func() bool { return o.len() == 0 }, 5*time.Second, time.Millisecond)
	require.Equal(t, int32(4), calls.Load())
	require.Equal(t, int32(1), signs.Load(), "voucher is signed once per entry")
	mu.Lock()
	for i := 1; i < len(notAfters); i++ {
		require.Greater(t, notAfters[i], notAfters[i-1], "not-after is rebuilt per attempt")
	}
	mu.Unlock()
	require.Contains(t, logs.String(), `"outcome":"retry"`)
	require.Contains(t, logs.String(), `"outcome":"registered"`)
}

// TestOutbox_NeverAttemptCapped: a coordinator that keeps failing keeps the
// entry pending with the interval at its cap.
func TestOutbox_NeverAttemptCapped(t *testing.T) {
	o, _, _ := testOutbox(t, func(context.Context, RegisterDelegateKeysBody) registrationOutcome {
		return registrationOutcome{status: http.StatusBadGateway}
	})
	require.NoError(t, o.enqueue("sealer-a", 1, "v1", testSeed(0)))
	for range 200 {
		o.attempt(context.Background(), o.next())
	}
	require.Equal(t, 1, o.len())
	require.Equal(t, 200, o.next().attempts)
}

// TestOutbox_BackoffIntervalCap: the interval doubles from the base and is
// capped at five minutes.
func TestOutbox_BackoffIntervalCap(t *testing.T) {
	o := newRegistrationOutbox(slog.Default(), nil, nil)
	require.Equal(t, 2*time.Second, o.backoff(1))
	require.Equal(t, 4*time.Second, o.backoff(2))
	require.Equal(t, 256*time.Second, o.backoff(8))
	require.Equal(t, 5*time.Minute, o.backoff(9))
	require.Equal(t, 5*time.Minute, o.backoff(10_000))
}

// TestOutbox_DedupeOnRepeatRequest: a repeat seed request for a pending
// (sealerId, epoch) upserts the one entry, keeps its signed voucher and makes
// it due now; another epoch is a separate entry.
func TestOutbox_DedupeOnRepeatRequest(t *testing.T) {
	o, _, signs := testOutbox(t, func(context.Context, RegisterDelegateKeysBody) registrationOutcome {
		return registrationOutcome{status: http.StatusBadGateway}
	})
	now := time.Unix(1_800_000_000, 0)
	o.now = func() time.Time { return now }

	require.NoError(t, o.enqueue("sealer-a", 1, "v1", testSeed(0)))
	o.attempt(context.Background(), o.next())
	require.True(t, o.next().nextAttempt.After(now), "failed attempt schedules a retry")

	require.NoError(t, o.enqueue("sealer-a", 1, "v1", testSeed(0)))
	require.Equal(t, 1, o.len())
	require.Equal(t, now, o.next().nextAttempt, "repeat request makes the entry due now")
	o.attempt(context.Background(), o.next())
	require.Equal(t, int32(1), signs.Load(), "voucher survives the upsert")

	require.NoError(t, o.enqueue("sealer-a", 2, "v2", testSeed(0)))
	require.NoError(t, o.enqueue("sealer-b", 1, "v1", testSeed(0)))
	require.Equal(t, 3, o.len())
}

// TestOutbox_CapOverflowLogsAndDrops: the 65th distinct entry is refused with
// an error log; upserts of existing entries still succeed at the cap.
func TestOutbox_CapOverflowLogsAndDrops(t *testing.T) {
	o, logs, _ := testOutbox(t, ok200)
	for e := range registrationOutboxCap {
		require.NoError(t, o.enqueue("sealer-a", uint32(e+1), "v", testSeed(0)))
	}
	err := o.enqueue("sealer-a", registrationOutboxCap+1, "v", testSeed(0))
	require.Error(t, err)
	require.Equal(t, registrationOutboxCap, o.len())
	require.Contains(t, logs.String(), `"level":"ERROR","msg":"delegate key registration outbox full; dropping entry"`)
	require.NoError(t, o.enqueue("sealer-a", 1, "v", testSeed(0)), "upsert at the cap")
}

// TestOutbox_ConflictIsTerminal: the coordinator's 409 (one key per
// (sealerId, epoch), canopy#267) drops the entry after one attempt, logs both
// hashes at error, and the worker never retries it.
func TestOutbox_ConflictIsTerminal(t *testing.T) {
	var calls atomic.Int32
	existing := "aa" + string(bytes.Repeat([]byte("0"), 62))
	o, logs, _ := testOutbox(t, func(_ context.Context, body RegisterDelegateKeysBody) registrationOutcome {
		calls.Add(1)
		b, _ := json.Marshal(map[string]any{
			"type":               "about:blank",
			"title":              "Conflict",
			"status":             409,
			"detail":             "sealer sealer-a epoch 1 already has delegate key " + existing,
			"sealerId":           body.SealerID,
			"epoch":              body.Keys[0].Epoch,
			"pubkeyHash":         "refused-hash",
			"existingPubkeyHash": existing,
		})
		return registrationOutcome{status: http.StatusConflict, body: b}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go o.run(ctx)
	require.NoError(t, o.enqueue("sealer-a", 1, "v1", testSeed(0)))
	require.Eventually(t, func() bool { return o.len() == 0 }, 5*time.Second, time.Millisecond)
	// Several backoff intervals: nothing is retried.
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, int32(1), calls.Load())

	out := logs.String()
	require.Contains(t, out, `"level":"ERROR"`)
	require.Contains(t, out, `"outcome":"conflict"`)
	require.Contains(t, out, `"existingPubkeyHash":"`+existing+`"`)
	require.Contains(t, out, `"refusedPubkeyHash":"refused-hash"`)
}

// TestOutbox_AttemptLogsAuditFields: every attempt logs sealerId, epoch,
// kmsKeyVersion, pubkey hash and outcome (ruling 4: the registrar's audit
// trail, not a control).
func TestOutbox_AttemptLogsAuditFields(t *testing.T) {
	o, logs, _ := testOutbox(t, ok200)
	seed := testSeed(0)
	require.NoError(t, o.enqueue("sealer-a", 2, "k/cryptoKeyVersions/2", seed))
	o.attempt(context.Background(), o.next())

	priv, err := delegatekeys.DeriveKey(seed, 2, 0)
	require.NoError(t, err)
	hash, err := delegatekeys.PubkeyHashHex(&priv.PublicKey)
	require.NoError(t, err)
	out := logs.String()
	for _, want := range []string{
		`"msg":"delegate key registration attempt"`,
		`"sealerId":"sealer-a"`,
		`"epoch":2`,
		`"kmsKeyVersion":"k/cryptoKeyVersions/2"`,
		`"pubkeyHash":"` + hash + `"`,
		`"outcome":"registered"`,
	} {
		require.Contains(t, out, want)
	}
}
