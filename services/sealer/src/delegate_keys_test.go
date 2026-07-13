package sealer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func testSeed(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// TestDeriveDelegateKey_Deterministic pins the load-bearing invariant: the
// same (seed, epoch, index) always yields the same P-256 key, so certificates
// bound to a delegate key survive restarts (ADR-0050 Q3).
func TestDeriveDelegateKey_Deterministic(t *testing.T) {
	seed := testSeed(t)
	k1, err := deriveDelegateKey(seed, 3, 0)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	k2, err := deriveDelegateKey(seed, 3, 0)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if k1.D.Cmp(k2.D) != 0 {
		t.Fatal("same (seed, epoch, index) must derive the same private scalar")
	}
	if k1.X.Cmp(k2.X) != 0 || k1.Y.Cmp(k2.Y) != 0 {
		t.Fatal("public points diverged for identical inputs")
	}
	// Valid scalar range and on-curve.
	n := k1.Curve.Params().N
	if k1.D.Sign() <= 0 || k1.D.Cmp(n) >= 0 {
		t.Fatalf("scalar out of range [1, n-1]")
	}
	if !k1.Curve.IsOnCurve(k1.X, k1.Y) {
		t.Fatal("derived public key is not on curve")
	}
}

// TestDeriveDelegateKey_DomainSeparation ensures epoch and index each change
// the derived key — rotation rotates, and multiple indices are independent.
func TestDeriveDelegateKey_DomainSeparation(t *testing.T) {
	seed := testSeed(t)
	base, _ := deriveDelegateKey(seed, 3, 0)
	byEpoch, _ := deriveDelegateKey(seed, 4, 0)
	byIndex, _ := deriveDelegateKey(seed, 3, 1)
	if base.D.Cmp(byEpoch.D) == 0 {
		t.Fatal("epoch bump must change the key")
	}
	if base.D.Cmp(byIndex.D) == 0 {
		t.Fatal("index bump must change the key")
	}
	// A different seed must diverge too.
	other, _ := deriveDelegateKey(testSeed(t), 3, 0)
	if base.D.Cmp(other.D) == 0 {
		t.Fatal("different seed must change the key")
	}
}

func TestDeriveDelegateKey_EmptySeed(t *testing.T) {
	if _, err := deriveDelegateKey(nil, 1, 0); err == nil {
		t.Fatal("empty seed must error")
	}
}

// TestLoadDelegateKeys_OverlapAndResolution checks that both epoch N and N-1
// keys are loaded (rotation overlap) and that KeyFor resolves a certificate's
// bound public key back to its private key — the Phase D lease-resolution
// contract that this Phase B code must satisfy.
func TestLoadDelegateKeys_OverlapAndResolution(t *testing.T) {
	local := localSeedProvider{secret: testSeed(t)}
	keys, err := LoadDelegateKeys(context.Background(), local, 5)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if keys.Current() == nil {
		t.Fatal("current key missing")
	}
	if len(keys.byPubkeyHash) != 2 {
		t.Fatalf("want epochs N and N-1 loaded, got %d keys", len(keys.byPubkeyHash))
	}
	// Current key resolves.
	if got := keys.KeyFor(&keys.Current().PublicKey); got == nil || got.D.Cmp(keys.Current().D) != 0 {
		t.Fatal("KeyFor failed to resolve the current key")
	}
	// The previous-epoch key resolves too.
	prevSeed, _ := local.Seed(context.Background(), 4)
	prev, _ := deriveDelegateKey(prevSeed, 4, 0)
	if got := keys.KeyFor(&prev.PublicKey); got == nil {
		t.Fatal("KeyFor failed to resolve the previous-epoch key")
	}
	// An unrelated key does not resolve.
	stranger, _ := ecdsa.GenerateKey(keys.Current().Curve, rand.Reader)
	if got := keys.KeyFor(&stranger.PublicKey); got != nil {
		t.Fatal("KeyFor resolved a key the sealer never held")
	}
}

func TestLoadDelegateKeys_Epoch1NoPrevious(t *testing.T) {
	local := localSeedProvider{secret: testSeed(t)}
	keys, err := LoadDelegateKeys(context.Background(), local, 1)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(keys.byPubkeyHash) != 1 {
		t.Fatalf("epoch 1 has no predecessor; want 1 key, got %d", len(keys.byPubkeyHash))
	}
}

func TestLoadDelegateKeys_ZeroEpoch(t *testing.T) {
	if _, err := LoadDelegateKeys(context.Background(), localSeedProvider{secret: []byte("x")}, 0); err == nil {
		t.Fatal("epoch 0 must error")
	}
}

// TestCustodianSeedProvider hits a fake custodian to confirm the CBOR request
// shape, bearer auth, and response decoding.
func TestCustodianSeedProvider(t *testing.T) {
	wantSeed := sha256.Sum256([]byte("fake-seed"))
	var gotReq delegateSeedRequest
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/delegate-seed" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = cbor.Unmarshal(body, &gotReq)
		out, _ := cbor.Marshal(delegateSeedResponse{Seed: wantSeed[:], KMSKeyVersion: "v/1"})
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(out)
	}))
	defer srv.Close()

	logger, _ := NewLogger(0)
	p := custodianSeedProvider{
		baseURL:    srv.URL,
		token:      "app-token",
		sealerID:   "sealer-a",
		httpClient: NewHTTPClient(logger),
	}
	seed, err := p.Seed(context.Background(), 7)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !bytes.Equal(seed, wantSeed[:]) {
		t.Fatal("seed mismatch")
	}
	if gotReq.SealerID != "sealer-a" || gotReq.Epoch != 7 {
		t.Fatalf("request shape = %+v", gotReq)
	}
	if gotAuth != "Bearer app-token" {
		t.Fatalf("auth = %q", gotAuth)
	}
}

func TestCustodianSeedProvider_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}))
	defer srv.Close()
	logger, _ := NewLogger(0)
	p := custodianSeedProvider{baseURL: srv.URL, token: "t", sealerID: "s", httpClient: NewHTTPClient(logger)}
	if _, err := p.Seed(context.Background(), 1); err == nil {
		t.Fatal("non-200 must error")
	}
}

func TestNewSeedProvider_Selection(t *testing.T) {
	logger, _ := NewLogger(0)
	hc := NewHTTPClient(logger)
	if p, err := NewSeedProvider(Config{DelegateSeedCustodianURL: "https://c"}, hc); err != nil {
		t.Fatalf("custodian: %v", err)
	} else if _, ok := p.(custodianSeedProvider); !ok {
		t.Fatal("want custodian provider")
	}
	if p, err := NewSeedProvider(Config{DelegateSeedLocal: []byte("s")}, hc); err != nil {
		t.Fatalf("local: %v", err)
	} else if _, ok := p.(localSeedProvider); !ok {
		t.Fatal("want local provider")
	}
	if _, err := NewSeedProvider(Config{}, hc); err == nil {
		t.Fatal("no source must error")
	}
}

// TestRegisterDelegateKeys confirms the registration shape (keys[] array),
// that both epochs N and N-1 are advertised with a rotation-spanning notAfter,
// and — the load-bearing property — that the advertised publicKey is the
// canonical COSE_Key CBOR whose sha256 equals the coordinator's
// delegated_pubkey_hash (review F1).
func TestRegisterDelegateKeys(t *testing.T) {
	var got DelegateKeyRegistration
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sealer/delegate-keys" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	local := localSeedProvider{secret: testSeed(t)}
	keys, _ := LoadDelegateKeys(context.Background(), local, 2)
	logger, _ := NewLogger(0)
	cfg := Config{
		SealerID:                 "sealer-a",
		DelegateKeyEpoch:         2,
		DelegateKeyTTL:           720 * time.Hour,
		CoordinatorRegisterURL:   srv.URL,
		CoordinatorRegisterToken: "reg-token",
	}
	const now = int64(1_800_000_000)
	registerDelegateKeys(context.Background(), NewHTTPClient(logger), logger, cfg, keys, now)

	if got.SealerID != "sealer-a" {
		t.Fatalf("sealerId = %q", got.SealerID)
	}
	if gotAuth != "Bearer reg-token" {
		t.Fatalf("auth = %q", gotAuth)
	}
	// Epoch 2 loads N=2 and N-1=1 (rotation overlap).
	if len(got.Keys) != 2 {
		t.Fatalf("want 2 keys (N, N-1), got %d", len(got.Keys))
	}
	wantNotAfter := now + int64((720 * time.Hour).Seconds())
	epochs := map[uint32]bool{}
	var current *DelegateKeyEntry
	for i := range got.Keys {
		e := &got.Keys[i]
		if e.Alg != "ES256" {
			t.Fatalf("alg = %q", e.Alg)
		}
		if e.NotAfter != wantNotAfter {
			t.Fatalf("notAfter = %d, want %d", e.NotAfter, wantNotAfter)
		}
		if _, err := base64.StdEncoding.DecodeString(e.PublicKey); err != nil {
			t.Fatalf("publicKey not base64: %v", err)
		}
		epochs[e.Epoch] = true
		if e.Epoch == 2 {
			current = e
		}
	}
	if !epochs[2] || !epochs[1] {
		t.Fatalf("want epochs {1,2}, got %v", epochs)
	}

	// The current key's advertised bytes must be the canonical COSE_Key CBOR,
	// and its sha256 must equal pubkeyHashHex — the coordinator's JOIN key.
	rawCurrent, _ := base64.StdEncoding.DecodeString(current.PublicKey)
	wantCose, err := delegateCoseKeyBytes(&keys.Current().PublicKey)
	if err != nil {
		t.Fatalf("cose encode: %v", err)
	}
	if !bytes.Equal(rawCurrent, wantCose) {
		t.Fatal("advertised publicKey is not the canonical COSE_Key CBOR")
	}
	wantHash, _ := pubkeyHashHex(&keys.Current().PublicKey)
	sum := sha256.Sum256(rawCurrent)
	if hex.EncodeToString(sum[:]) != wantHash {
		t.Fatal("sha256(publicKey) != pubkeyHashHex (JOIN key would not match)")
	}
}

// TestRegisterDelegateKeys_BestEffort ensures registration never panics or
// blocks when the coordinator is unreachable or rejects.
func TestRegisterDelegateKeys_BestEffort(t *testing.T) {
	local := localSeedProvider{secret: testSeed(t)}
	keys, _ := LoadDelegateKeys(context.Background(), local, 1)
	logger, _ := NewLogger(0)

	// Rejecting coordinator.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	registerDelegateKeys(context.Background(), NewHTTPClient(logger), logger,
		Config{SealerID: "s", DelegateKeyTTL: time.Hour, CoordinatorRegisterURL: srv.URL}, keys, 1)

	// No URL configured.
	registerDelegateKeys(context.Background(), NewHTTPClient(logger), logger, Config{}, keys, 1)
}

// TestStartDelegateKeySchedule_Disabled confirms the feature is entirely off
// at epoch 0 (no seed source needed, no key set returned).
func TestStartDelegateKeySchedule_Disabled(t *testing.T) {
	logger, _ := NewLogger(0)
	keys, err := StartDelegateKeySchedule(context.Background(), NewHTTPClient(logger), logger, Config{DelegateKeyEpoch: 0})
	if err != nil {
		t.Fatalf("disabled must not error: %v", err)
	}
	if keys != nil {
		t.Fatal("disabled must return nil key set")
	}
}

// TestStartDelegateKeySchedule_LocalSeed exercises the full boot path with the
// self-hosted seed source and a fake coordinator.
func TestStartDelegateKeySchedule_LocalSeed(t *testing.T) {
	registered := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registered = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	logger, _ := NewLogger(0)
	cfg := Config{
		SealerID:               "sealer-a",
		DelegateKeyEpoch:       3,
		DelegateKeyTTL:         720 * time.Hour,
		DelegateSeedLocal:      testSeed(t),
		CoordinatorRegisterURL: srv.URL,
	}
	keys, err := StartDelegateKeySchedule(context.Background(), NewHTTPClient(logger), logger, cfg)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if keys == nil || keys.Current() == nil {
		t.Fatal("expected loaded key set")
	}
	if !registered {
		t.Fatal("expected coordinator registration attempt")
	}
}
