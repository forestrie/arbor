package sealer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
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

// TestDelegateKeySet_HeldPubkeyHashes: the issue request's heldPublicKeyHashes
// (FOR-586) must name exactly the keys KeyFor can resolve, epoch N first, so
// the coordinator never serves a certificate the sealer cannot sign with.
func TestDelegateKeySet_HeldPubkeyHashes(t *testing.T) {
	local := localSeedProvider{secret: testSeed(t)}
	keys, err := LoadDelegateKeys(context.Background(), local, 5)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	held := keys.HeldPubkeyHashes()
	if len(held) != 2 {
		t.Fatalf("want 2 held hashes (epochs 5 and 4), got %d", len(held))
	}
	currentHash, _ := pubkeyHashHex(&keys.Current().PublicKey)
	if held[0] != currentHash {
		t.Fatal("epoch N must be advertised first")
	}
	for _, h := range held {
		if _, ok := keys.byPubkeyHash[h]; !ok {
			t.Fatalf("held hash %s does not resolve to a held key", h)
		}
	}
	var nilSet *DelegateKeySet
	if got := nilSet.HeldPubkeyHashes(); got != nil {
		t.Fatal("nil set (on-demand model) must advertise no held keys")
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

// fakeCustodian serves deterministic per-epoch seeds and answers the epochs
// in retired with the custodian's 409, and those in failing with a 500.
func fakeCustodian(t *testing.T, retired, failing map[uint32]bool) custodianSeedProvider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req delegateSeedRequest
		body, _ := io.ReadAll(r.Body)
		_ = cbor.Unmarshal(body, &req)
		switch {
		case retired[req.Epoch]:
			w.WriteHeader(http.StatusConflict)
			return
		case failing[req.Epoch]:
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		seed := sha256.Sum256([]byte(fmt.Sprintf("seed/%d", req.Epoch)))
		out, _ := cbor.Marshal(delegateSeedResponse{Seed: seed[:], KMSKeyVersion: fmt.Sprintf("k/cryptoKeyVersions/%d", req.Epoch)})
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	logger, _ := NewLogger(0)
	return custodianSeedProvider{baseURL: srv.URL, token: "t", sealerID: "sealer-a", httpClient: NewHTTPClient(logger), logger: logger}
}

// TestLoadDelegateKeys_RetiredPrevious: once the operator disables the N-1
// key version (plan-2609-11 runbook step 4) the sealer must still boot, with
// epoch N alone.
func TestLoadDelegateKeys_RetiredPrevious(t *testing.T) {
	p := fakeCustodian(t, map[uint32]bool{4: true}, nil)
	keys, err := LoadDelegateKeys(context.Background(), p, 5)
	if err != nil {
		t.Fatalf("load with retired N-1 must succeed: %v", err)
	}
	if keys.Current() == nil || len(keys.byPubkeyHash) != 1 {
		t.Fatalf("want epoch N only; got %d keys, current=%v", len(keys.byPubkeyHash), keys.Current() != nil)
	}
	if !keys.PreviousRetired() {
		t.Fatal("PreviousRetired must report the refused N-1")
	}
}

// A retired CURRENT epoch is an operator error (the sealer was bumped to an
// epoch whose version does not exist or is disabled): fail the load.
func TestLoadDelegateKeys_RetiredCurrentFails(t *testing.T) {
	p := fakeCustodian(t, map[uint32]bool{5: true}, nil)
	if _, err := LoadDelegateKeys(context.Background(), p, 5); err == nil {
		t.Fatal("retired current epoch must fail the load")
	}
}

// A transient failure for N-1 is NOT retirement: fail the load so the boot
// retry runs again rather than silently dropping the overlap.
func TestLoadDelegateKeys_TransientPreviousFails(t *testing.T) {
	p := fakeCustodian(t, nil, map[uint32]bool{4: true})
	_, err := LoadDelegateKeys(context.Background(), p, 5)
	if err == nil {
		t.Fatal("transient N-1 failure must fail the load")
	}
	if errors.Is(err, errDelegateSeedEpochRetired) {
		t.Fatal("a 500 must not be reported as retired")
	}
}

func TestCustodianSeedProvider_RetiredIs409(t *testing.T) {
	p := fakeCustodian(t, map[uint32]bool{3: true}, nil)
	_, err := p.Seed(context.Background(), 3)
	if !errors.Is(err, errDelegateSeedEpochRetired) {
		t.Fatalf("409 must map to errDelegateSeedEpochRetired, got %v", err)
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

// The advertised COSE_Key ⇄ delegated_pubkey_hash equality (former review F1)
// is now proven by the shared delegatekeys golden-vector test and the
// custodian's registration test; the sealer no longer self-registers (the
// custodian registers the standing key + voucher at seed issuance, FOR-390
// phase G3/G4).

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

// TestStartDelegateKeySchedule_LocalSeed exercises the full boot load path with
// the self-hosted seed source. The sealer loads the standing keys but no longer
// registers them (the custodian does — FOR-390 phase G3/G4).
func TestStartDelegateKeySchedule_LocalSeed(t *testing.T) {
	logger, _ := NewLogger(0)
	cfg := Config{
		SealerID:          "sealer-a",
		DelegateKeyEpoch:  3,
		DelegateKeyTTL:    720 * time.Hour,
		DelegateSeedLocal: testSeed(t),
	}
	keys, err := StartDelegateKeySchedule(context.Background(), NewHTTPClient(logger), logger, cfg)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if keys == nil || keys.Current() == nil {
		t.Fatal("expected loaded key set")
	}
}
