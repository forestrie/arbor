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

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"golang.org/x/crypto/hkdf"
)

// deriveDelegateKey deterministically derives the standing delegate key
// (epoch, index) from the KMS-derived seed (ADR-0050 / plan-2607-20 phase B).
// The same (seed, epoch, index) always yields the same key, so certificates
// bound to it survive process restarts — no delegate private material is ever
// at rest.
//
// Hash-to-scalar uses the RFC 9380 §5 expand-then-reduce construction: draw 40
// bytes (320 bits) from HKDF and reduce mod (n-1), +1, so the scalar is in
// [1, n-1] with negligible modular bias (~2^-64). The coordinator never
// re-derives this key (it only stores the public half the sealer registers),
// so there is no cross-implementation determinism requirement — only
// self-consistency across restarts, which the fixed info string guarantees.
func deriveDelegateKey(seed []byte, epoch uint32, index uint8) (*ecdsa.PrivateKey, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("empty delegate seed")
	}
	curve := elliptic.P256()
	n := curve.Params().N
	info := fmt.Sprintf("forestrie/delegate-key/v1/%d/%d", epoch, index)
	r := hkdf.New(sha256.New, seed, nil, []byte(info))
	buf := make([]byte, 40) // 320 bits: bound modular bias before the range map
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
	if priv.X.Sign() == 0 {
		// Unreachable for a scalar in [1, n-1] on P-256; guard defensively.
		return nil, fmt.Errorf("delegate key derivation produced identity (epoch=%d index=%d)", epoch, index)
	}
	return priv, nil
}

// delegateCoseKeyBytes encodes the delegate public key as the canonical
// (RFC 8949 §4.2) COSE_Key CBOR — byte-identical to what a signer binds into a
// delegation certificate, so its sha256 equals the coordinator's
// delegated_pubkey_hash and the certificate↔delegate-key JOIN matches.
func delegateCoseKeyBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	coseKey, err := delegationcert.NewDelegatedCoseKey(delegationcert.Secp256r1, x, y)
	if err != nil {
		return nil, err
	}
	return canonicalCBOR.Marshal(coseKey.ToCBORMap())
}

// pubkeyHashHex is the identity the coordinator stores as
// delegated_pubkey_hash: hex(sha256(canonical COSE_Key CBOR)).
func pubkeyHashHex(pub *ecdsa.PublicKey) (string, error) {
	b, err := delegateCoseKeyBytes(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
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

// delegateKeyEntry is a standing delegate key with the epoch it belongs to.
type delegateKeyEntry struct {
	epoch uint32
	priv  *ecdsa.PrivateKey
}

// DelegateKeySet holds the standing delegate keys the sealer can sign with,
// indexed by the coordinator's delegated_pubkey_hash so a certificate bound
// to any of them resolves back to its private key (plan-2607-20 phase D).
type DelegateKeySet struct {
	byPubkeyHash map[string]*ecdsa.PrivateKey
	entries      []delegateKeyEntry // epoch N then N-1, in advertise order
	current      *ecdsa.PrivateKey  // epoch N, index 0 — the advertised key
	currentEpoch uint32
}

// Current returns the advertised delegate key (epoch N, index 0).
func (s *DelegateKeySet) Current() *ecdsa.PrivateKey { return s.current }

// KeyFor returns the private key for a certificate-bound public key, or nil.
func (s *DelegateKeySet) KeyFor(pub *ecdsa.PublicKey) *ecdsa.PrivateKey {
	if s == nil {
		return nil
	}
	h, err := pubkeyHashHex(pub)
	if err != nil {
		return nil
	}
	return s.byPubkeyHash[h]
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
		h, err := pubkeyHashHex(&k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("hash delegate key for epoch %d: %w", e, err)
		}
		s.byPubkeyHash[h] = k
		s.entries = append(s.entries, delegateKeyEntry{epoch: e, priv: k})
		if e == epoch {
			s.current = k
		}
	}
	return s, nil
}
