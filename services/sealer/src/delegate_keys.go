package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// deriveDelegateKey deterministically derives the standing delegate key
// (epoch, index) from the KMS-derived seed (ADR-0050 / plan-2607-20 phase B).
// The same (seed, epoch, index) always yields the same key, so certificates
// bound to it survive process restarts — no delegate private material is ever
// at rest. Uses HKDF-expand with rejection sampling so the scalar is uniform
// in [1, n-1].
func deriveDelegateKey(seed []byte, epoch uint32, index uint8) (*ecdsa.PrivateKey, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("empty delegate seed")
	}
	curve := elliptic.P256()
	n := curve.Params().N
	info := fmt.Sprintf("forestrie/delegate-key/v1/%d/%d", epoch, index)
	for counter := 0; counter < 256; counter++ {
		r := hkdf.New(sha256.New, seed, nil, []byte(fmt.Sprintf("%s/%d", info, counter)))
		buf := make([]byte, 40) // 320 bits: reduce modular bias before the range check
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(buf)
		k.Mod(k, new(big.Int).Sub(n, big.NewInt(1)))
		k.Add(k, big.NewInt(1)) // k ∈ [1, n-1]
		priv := new(ecdsa.PrivateKey)
		priv.Curve = curve
		priv.D = k
		priv.X, priv.Y = curve.ScalarBaseMult(k.Bytes())
		if priv.X.Sign() != 0 {
			return priv, nil
		}
	}
	return nil, fmt.Errorf("delegate key derivation failed (epoch=%d index=%d)", epoch, index)
}

// pubkeyHashHex is the identity the coordinator stores as
// delegated_pubkey_hash: hex(sha256(uncompressed P-256 point)).
func pubkeyHashHex(pub *ecdsa.PublicKey) string {
	uncompressed := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	sum := sha256.Sum256(uncompressed)
	return hex.EncodeToString(sum[:])
}

// pubkeyXYBytes returns the 64-byte x||y encoding used on the wire.
func pubkeyXYBytes(pub *ecdsa.PublicKey) []byte {
	out := make([]byte, 64)
	pub.X.FillBytes(out[:32])
	pub.Y.FillBytes(out[32:])
	return out
}

// SeedProvider yields the delegate-key seed for an epoch. Implementations:
// the custodian KMS-MAC endpoint (production) and a locally-held seed
// (self-hosted sealers).
type SeedProvider interface {
	Seed(ctx context.Context, epoch uint32) ([]byte, error)
}

// localSeedProvider serves a fixed seed for all epochs mixed with the epoch
// (self-hosted escape hatch; DELEGATE_SEED). It preserves per-epoch
// distinctness by HKDF-mixing the epoch into the configured secret.
type localSeedProvider struct{ secret []byte }

func (p localSeedProvider) Seed(_ context.Context, epoch uint32) ([]byte, error) {
	if len(p.secret) == 0 {
		return nil, fmt.Errorf("DELEGATE_SEED is empty")
	}
	r := hkdf.New(sha256.New, p.secret, nil, []byte(fmt.Sprintf("forestrie/delegate-seed/local/%d", epoch)))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// DelegateKeySet holds the standing delegate keys the sealer can sign with,
// indexed by the coordinator's delegated_pubkey_hash so a certificate bound
// to any of them resolves back to its private key (plan-2607-20 phase D).
type DelegateKeySet struct {
	byPubkeyHash map[string]*ecdsa.PrivateKey
	current      *ecdsa.PrivateKey // epoch N, index 0 — the advertised key
	currentEpoch uint32
}

// Current returns the advertised delegate key (epoch N, index 0).
func (s *DelegateKeySet) Current() *ecdsa.PrivateKey { return s.current }

// KeyFor returns the private key for a certificate-bound public key, or nil.
func (s *DelegateKeySet) KeyFor(pub *ecdsa.PublicKey) *ecdsa.PrivateKey {
	if s == nil {
		return nil
	}
	return s.byPubkeyHash[pubkeyHashHex(pub)]
}

// LoadDelegateKeys derives epochs N and N-1 (overlap so rotation never
// strands unexpired certificates) from the seed provider.
func LoadDelegateKeys(ctx context.Context, provider SeedProvider, epoch uint32) (*DelegateKeySet, error) {
	if epoch == 0 {
		return nil, fmt.Errorf("delegate key epoch must be >= 1")
	}
	s := &DelegateKeySet{byPubkeyHash: map[string]*ecdsa.PrivateKey{}, currentEpoch: epoch}
	epochs := []uint32{epoch}
	if epoch > 1 {
		epochs = append(epochs, epoch-1)
	}
	for _, e := range epochs {
		seed, err := provider.Seed(ctx, e)
		if err != nil {
			return nil, fmt.Errorf("seed for epoch %d: %w", e, err)
		}
		k, err := deriveDelegateKey(seed, e, 0)
		if err != nil {
			return nil, err
		}
		s.byPubkeyHash[pubkeyHashHex(&k.PublicKey)] = k
		if e == epoch {
			s.current = k
		}
	}
	return s, nil
}
