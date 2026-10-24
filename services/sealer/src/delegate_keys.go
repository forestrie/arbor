package sealer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
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
// (tests).
type SeedProvider interface {
	Seed(ctx context.Context, epoch uint32) (DelegateSeed, error)
}

// DelegateSeed is one epoch's seed and, from the custodian, the registrar
// voucher for the key it derives (delegate-seed apiVersion 3, devdocs
// plan-2609-12 slice 07). Voucher is nil for the local seed, and when the
// custodian could not sign one.
type DelegateSeed struct {
	Seed    []byte
	Voucher *DelegateKeyVoucher
}

// localSeedProvider serves a fixed seed for all epochs mixed with the epoch,
// preserving per-epoch distinctness by HKDF-mixing the epoch into the secret.
//
// NOTE (FOR-390 phase J3): this is a TEST-ONLY seam (DELEGATE_SEED), not a
// production deployment path. Self-hosted sealing is direct K(L) signing, not
// delegation (ADR-0050 §"Trust model"), so a self-hoster never derives delegate
// seeds; the production delegation path is custodian-gated only. It is retained
// as a hermetic seed source for tests.
type localSeedProvider struct{ secret []byte }

// Seed derives epoch's seed from the local secret. It carries no voucher.
func (p localSeedProvider) Seed(_ context.Context, epoch uint32) (DelegateSeed, error) {
	if len(p.secret) == 0 {
		return DelegateSeed{}, fmt.Errorf("DELEGATE_SEED is empty")
	}
	r := hkdf.New(sha256.New, p.secret, nil, []byte(fmt.Sprintf("forestrie/delegate-seed/local/%d", epoch)))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return DelegateSeed{}, err
	}
	return DelegateSeed{Seed: out}, nil
}

// delegateKeyEntry is a standing delegate key with the epoch it belongs to,
// and the voucher that came with its seed (nil for the local seed, or when
// the custodian could not sign one).
type delegateKeyEntry struct {
	epoch      uint32
	priv       *ecdsa.PrivateKey
	coseKey    []byte // canonical COSE_Key: the registration's publicKey
	pubkeyHash string
	voucher    *DelegateKeyVoucher
}

// DelegateKeySet holds the standing delegate keys the sealer can sign with,
// indexed by the coordinator's delegated_pubkey_hash so a certificate bound
// to any of them resolves back to its private key (plan-2607-20 phase D).
type DelegateKeySet struct {
	byPubkeyHash map[string]*ecdsa.PrivateKey
	entries      []delegateKeyEntry // epoch N then N-1, in advertise order
	current      *ecdsa.PrivateKey  // epoch N, index 0 — the advertised key
	currentEpoch uint32
	// previousRetired records that the custodian refused epoch N-1 as retired
	// (its MAC key version is disabled or destroyed), so the set holds epoch N
	// only. Certificates still bound to the N-1 key cannot be signed with.
	previousRetired bool
}

// Current returns the advertised delegate key (epoch N, index 0).
func (s *DelegateKeySet) Current() *ecdsa.PrivateKey { return s.current }

// PreviousRetired reports whether epoch N-1 was refused as retired at load.
func (s *DelegateKeySet) PreviousRetired() bool { return s != nil && s.previousRetired }

// HeldPubkeyHashes returns the coordinator identities (delegated_pubkey_hash)
// of every key in the set, epoch N first, for the issue request's
// heldPublicKeyHashes (FOR-586): the coordinator must not serve a certificate
// bound to a key the sealer cannot sign with.
func (s *DelegateKeySet) HeldPubkeyHashes() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.entries))
	for _, e := range s.entries {
		h, err := pubkeyHashHex(&e.priv.PublicKey)
		if err != nil {
			continue
		}
		out = append(out, h)
	}
	return out
}

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
//
// A retired epoch N-1 (the custodian's 409: its KMS key version has been
// disabled after the overlap ran its course, plan-2609-11) is not an error:
// the set loads with epoch N alone and PreviousRetired reports it. Any other
// N-1 failure, and any failure for epoch N, fails the load so the boot-time
// retry keeps trying. So does a voucher that binds a key other than the one
// its seed derives (devdocs plan-2609-12 slice 05 change 2).
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
			if e != epoch && errors.Is(err, errDelegateSeedEpochRetired) {
				s.previousRetired = true
				continue
			}
			return nil, fmt.Errorf("seed for epoch %d: %w", e, err)
		}
		k, err := deriveDelegateKey(seed.Seed, e, 0)
		if err != nil {
			return nil, err
		}
		coseKey, err := delegateCoseKeyBytes(&k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("encode delegate key for epoch %d: %w", e, err)
		}
		h, err := pubkeyHashHex(&k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("hash delegate key for epoch %d: %w", e, err)
		}
		if seed.Voucher != nil && !bytes.Equal(seed.Voucher.CoseKey, coseKey) {
			return nil, fmt.Errorf("seed for epoch %d: voucher binds a key other than the derived key %s; refusing the response", e, h)
		}
		s.byPubkeyHash[h] = k
		s.entries = append(s.entries, delegateKeyEntry{epoch: e, priv: k, coseKey: coseKey, pubkeyHash: h, voucher: seed.Voucher})
		if e == epoch {
			s.current = k
		}
	}
	return s, nil
}
