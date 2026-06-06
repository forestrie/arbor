package univocity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fxamacker/cbor/v2"
)

// ERC1271Verifier supports KS256 contract-wallet signature checks (Safe, etc.).
type ERC1271Verifier interface {
	HasCode(ctx context.Context, addr common.Address) (bool, error)
	IsValidSignature(ctx context.Context, addr common.Address, hash, sig []byte) error
}

// verifyGrantEnvelope verifies a grant COSE Sign1 against an opaque owner root
// identity (ES256 x||y or KS256 address).
func verifyGrantEnvelope(
	ctx context.Context,
	cose coseSign1,
	ownerAlg int64,
	ownerKey []byte,
	verifier ERC1271Verifier,
) error {
	protAlg, err := algFromProtectedHeader(cose.protected)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGrantSignatureInvalid, err)
	}
	if protAlg != ownerAlg {
		return fmt.Errorf("%w: protected alg %d != owner alg %d",
			ErrGrantSignatureInvalid, protAlg, ownerAlg)
	}
	switch ownerAlg {
	case coseAlgES256:
		x, y, ok := grantDataToXY(ownerKey)
		if !ok {
			return errors.New("owner ES256 key is not 64 bytes")
		}
		return verifyCoseSign1ES256(cose, x, y)
	case coseAlgKS256:
		if len(ownerKey) != 20 {
			return errors.New("owner KS256 key is not 20 bytes")
		}
		return verifyCoseSign1KS256(ctx, cose, ownerKey, verifier)
	default:
		return fmt.Errorf("unsupported owner alg %d", ownerAlg)
	}
}

// verifyCoseSign1KS256 verifies a COSE Sign1 KS256 signature against a 20-byte
// Ethereum address using keccak256 Sig_structure + ecrecover or ERC-1271.
func verifyCoseSign1KS256(
	ctx context.Context,
	cose coseSign1,
	signerAddr []byte,
	verifier ERC1271Verifier,
) error {
	if len(signerAddr) != 20 {
		return fmt.Errorf("%w: KS256 signer must be 20 bytes", ErrGrantSignatureInvalid)
	}
	sigStructure := []interface{}{
		"Signature1",
		cose.protected,
		[]byte{},
		cose.payload,
	}
	sigBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("encode sig structure: %w", err)
	}
	hash := crypto.Keccak256(sigBytes)
	addr := common.BytesToAddress(signerAddr)

	if verifier != nil {
		hasCode, err := verifier.HasCode(ctx, addr)
		if err != nil {
			return fmt.Errorf("erc1271 code check: %w", err)
		}
		if hasCode {
			if err := verifier.IsValidSignature(ctx, addr, hash, cose.signature); err != nil {
				return fmt.Errorf("%w: %v", ErrGrantSignatureInvalid, err)
			}
			return nil
		}
	}

	if len(cose.signature) != 65 {
		return fmt.Errorf("%w: KS256 EOA signature must be 65 bytes", ErrGrantSignatureInvalid)
	}
	pub, err := crypto.SigToPub(hash, cose.signature)
	if err != nil {
		return fmt.Errorf("%w: ecrecover failed: %v", ErrGrantSignatureInvalid, err)
	}
	recovered := crypto.PubkeyToAddress(*pub)
	if recovered != addr {
		return ErrGrantSignatureInvalid
	}
	return nil
}

func algFromProtectedHeader(protected []byte) (int64, error) {
	var top interface{}
	if err := cbor.Unmarshal(protected, &top); err != nil {
		return 0, fmt.Errorf("decode protected header: %w", err)
	}
	m := decodeCBORIntKeyMap(top)
	if m == nil {
		return 0, errors.New("protected header must be a map")
	}
	alg, ok := m.int(1) // COSE protected header alg label
	if !ok {
		return 0, errors.New("protected header missing alg (key 1)")
	}
	return alg, nil
}

// grantDataIdentity maps grantData bytes to (alg, key) using length rules.
func grantDataIdentity(grantData []byte) (alg int64, key []byte, ok bool) {
	switch len(grantData) {
	case 64:
		out := make([]byte, 64)
		copy(out, grantData)
		return coseAlgES256, out, true
	case 20:
		out := make([]byte, 20)
		copy(out, grantData)
		return coseAlgKS256, out, true
	default:
		return 0, nil, false
	}
}

// bootstrapIdentityFromKey infers alg from opaque bootstrap key length.
func bootstrapIdentityFromKey(key []byte) (alg int64, ok bool) {
	switch len(key) {
	case 64:
		return coseAlgES256, true
	case 20:
		return coseAlgKS256, true
	default:
		return 0, false
	}
}

// verifyCoseSign1ES256 verifies a COSE Sign1 ES256 signature against the
// provided P-256 public key coordinates.
func verifyCoseSign1ES256(cose coseSign1, x, y [32]byte) error {
	if len(cose.signature) != 64 {
		return fmt.Errorf("%w: COSE signature must be 64 bytes", ErrGrantSignatureInvalid)
	}
	pub, err := ecdsaPubFromXY(x, y)
	if err != nil {
		return err
	}
	sigStructure := []interface{}{
		"Signature1",
		cose.protected,
		[]byte{},
		cose.payload,
	}
	sigBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("encode sig structure: %w", err)
	}
	digest := sha256.Sum256(sigBytes)
	r := new(big.Int).SetBytes(cose.signature[:32])
	s := new(big.Int).SetBytes(cose.signature[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return ErrGrantSignatureInvalid
	}
	return nil
}

// ecdsaPubFromXY builds a P-256 public key from 32-byte big-endian coordinates.
func ecdsaPubFromXY(x, y [32]byte) (*ecdsa.PublicKey, error) {
	bx := new(big.Int).SetBytes(x[:])
	by := new(big.Int).SetBytes(y[:])
	curve := elliptic.P256()
	if !curve.IsOnCurve(bx, by) {
		return nil, errors.New("public key point is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: curve, X: bx, Y: by}, nil
}

// grantDataToXY splits a 64-byte ES256 grantData (x||y) into coordinates.
func grantDataToXY(grantData []byte) (x, y [32]byte, ok bool) {
	if len(grantData) != 64 {
		return [32]byte{}, [32]byte{}, false
	}
	copy(x[:], grantData[:32])
	copy(y[:], grantData[32:])
	return x, y, true
}

func bootstrapKeysEqual(algA int64, keyA []byte, algB int64, keyB []byte) bool {
	return algA == algB && bytes.Equal(keyA, keyB)
}
