// Package delegatekeys is the single source of truth for deriving a sealer's
// standing delegate keys and for computing the public-key identity the
// delegation coordinator stores as delegated_pubkey_hash.
//
// Both the sealer (which holds the private keys and signs checkpoints) and the
// custodian (which re-derives the public keys at seed issuance to register and
// vouch for them — FOR-390 phase G) import this package, so the two can never
// drift. Drift would be silent and expensive: registered public keys that do
// not match the sealer's keys make every coverage-retrieval lookup miss, and
// the sealer falls back to on-demand issuance with no error anywhere. The
// golden-vector test in this package pins the wire so a change on either side
// is caught in CI.
//
// See ADR-0050 (§"Trust model and genesis topology") and plan-2607-20 phase G.
package delegatekeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
)

// deriveInfoPrefix is the fixed HKDF info-string prefix for standing delegate
// keys. It is part of the wire contract: changing it changes every derived
// key. Keep it identical across sealer and custodian.
const deriveInfoPrefix = "forestrie/delegate-key/v1"

// canonicalCBOR is the RFC 8949 §4.2 core-deterministic encoder (bytewise key
// ordering, definite lengths, shortest-form). The COSE_Key bytes it produces
// MUST be byte-identical to what a signer binds into a delegation certificate,
// so their sha256 equals the coordinator's delegated_pubkey_hash and the
// certificate ↔ delegate-key JOIN matches. This mirrors the sealer's
// cbor_encmode.go exactly.
var canonicalCBOR cbor.EncMode

func init() {
	em, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	if err != nil {
		panic(fmt.Errorf("delegatekeys: build canonical CBOR EncMode: %w", err))
	}
	canonicalCBOR = em
}

// DeriveKey deterministically derives the standing delegate key (epoch, index)
// from the KMS-derived seed. The same (seed, epoch, index) always yields the
// same key, so certificates bound to it survive process restarts — no delegate
// private material is ever at rest.
//
// Hash-to-scalar uses the RFC 9380 §5 expand-then-reduce construction: draw 40
// bytes (320 bits) from HKDF and reduce mod (n-1), +1, so the scalar is in
// [1, n-1] with negligible modular bias (~2^-64).
func DeriveKey(seed []byte, epoch uint32, index uint8) (*ecdsa.PrivateKey, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("empty delegate seed")
	}
	curve := elliptic.P256()
	n := curve.Params().N
	info := fmt.Sprintf("%s/%d/%d", deriveInfoPrefix, epoch, index)
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

// CoseKeyBytes encodes the delegate public key as the canonical (RFC 8949
// §4.2) COSE_Key CBOR — byte-identical to what a signer binds into a delegation
// certificate, so its sha256 equals the coordinator's delegated_pubkey_hash.
func CoseKeyBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, fmt.Errorf("nil delegate public key")
	}
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

// PubkeyHashHex is the identity the coordinator stores as delegated_pubkey_hash:
// hex(sha256(canonical COSE_Key CBOR)).
func PubkeyHashHex(pub *ecdsa.PublicKey) (string, error) {
	b, err := CoseKeyBytes(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
