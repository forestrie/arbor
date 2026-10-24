package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"
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
	prev, _ := deriveDelegateKey(prevSeed.Seed, 4, 0)
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
		t.Fatal("nil set must advertise no held keys")
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

// The local seed carries no voucher: there is no registration to assert.
func TestLoadDelegateKeys_LocalSeedHasNoVoucher(t *testing.T) {
	keys, err := LoadDelegateKeys(context.Background(), localSeedProvider{secret: testSeed(t)}, 5)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, e := range keys.entries {
		if e.voucher != nil {
			t.Fatalf("epoch %d: local seed must carry no voucher", e.epoch)
		}
	}
}

// TestNewSeedProvider_Selection pins the seed source choice, which also
// decides whether the sealer asserts registration (slice 05 change 9).
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
