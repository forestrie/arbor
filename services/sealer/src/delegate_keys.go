package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/forestrie/arbor/services/pkgs/delegatekeys"
	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"golang.org/x/crypto/hkdf"
)

// deriveDelegateKey / delegateCoseKeyBytes / pubkeyHashHex delegate to the
// shared delegatekeys package (FOR-390 phase G). That package is the single
// source of truth so the sealer (which holds the private keys) and the
// custodian (which re-derives the public keys to register and vouch for them)
// can never drift; a drift would silently break coverage retrieval. These
// thin wrappers keep the existing call sites unchanged.
func deriveDelegateKey(seed []byte, epoch uint32, index uint8) (*ecdsa.PrivateKey, error) {
	return delegatekeys.DeriveKey(seed, epoch, index)
}

// delegateCoseKeyBytes encodes the delegate public key as the canonical
// (RFC 8949 §4.2) COSE_Key CBOR — byte-identical to what a signer binds into a
// delegation certificate.
func delegateCoseKeyBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	return delegatekeys.CoseKeyBytes(pub)
}

// ecdsaFromDelegatedCoseKey reconstructs a P-256 public key from a certificate's
// parsed delegated COSE_Key so it can be resolved against the standing set via
// KeyFor (FOR-390 phase D / B4).
func ecdsaFromDelegatedCoseKey(dk *delegationcert.DelegatedCoseKey) (*ecdsa.PublicKey, error) {
	if dk == nil || len(dk.X) == 0 || len(dk.Y) == 0 {
		return nil, fmt.Errorf("delegated cose key missing coordinates")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(dk.X),
		Y:     new(big.Int).SetBytes(dk.Y),
	}, nil
}

// pubkeyHashHex is the identity the coordinator stores as
// delegated_pubkey_hash: hex(sha256(canonical COSE_Key CBOR)).
func pubkeyHashHex(pub *ecdsa.PublicKey) (string, error) {
	return delegatekeys.PubkeyHashHex(pub)
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
