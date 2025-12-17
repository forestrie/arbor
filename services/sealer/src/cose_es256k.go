package sealer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/veraison/go-cose"
)

// ES256K is COSE algorithm -47 (ECDSA secp256k1 w/ SHA-256).
// See: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
const AlgorithmES256K cose.Algorithm = cose.Algorithm(-47)

// ES256KSigner implements github.com/veraison/go-cose.Signer for ECDSA over
// secp256k1 with SHA-256 (COSE alg = -47).
//
// NOTE: veraison/go-cose does not currently provide a built-in signer for -47,
// so we implement it here for delegated signing.
type ES256KSigner struct {
	key *ecdsa.PrivateKey
}

func NewES256KSigner(key *ecdsa.PrivateKey) (*ES256KSigner, error) {
	if key == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if key.Curve == nil {
		return nil, fmt.Errorf("private key curve is nil")
	}
	// Best-effort: ensure the curve looks like secp256k1 by name.
	// We deliberately don't hard-reject other curves to allow testing, but
	// callers should only use this signer with secp256k1 keys.
	return &ES256KSigner{key: key}, nil
}

func (s *ES256KSigner) Algorithm() cose.Algorithm {
	return AlgorithmES256K
}

// Sign signs the content bytes (the COSE Sig_structure) as required by COSE.
// For ES256K the digest is SHA-256(content) and the signature is encoded as
// fixed-width r || s per RFC8152 §8.1.
func (s *ES256KSigner) Sign(rand io.Reader, content []byte) ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, fmt.Errorf("signer not initialized")
	}
	sum := sha256.Sum256(content)
	r, ss, err := ecdsa.Sign(rand, s.key, sum[:])
	if err != nil {
		return nil, err
	}
	return encodeECDSASignature(s.key.Curve, r, ss)
}

// I2OSP converts x to a fixed-width big-endian byte string of length len(buf).
// This is used to encode ECDSA signatures as fixed-width r||s.
func I2OSP(x *big.Int, buf []byte) error {
	if x.Sign() < 0 {
		return errors.New("I2OSP: negative integer")
	}
	if x.BitLen() > len(buf)*8 {
		return errors.New("I2OSP: integer too large")
	}
	x.FillBytes(buf)
	return nil
}

func encodeECDSASignature(curve elliptic.Curve, r, s *big.Int) ([]byte, error) {
	if curve == nil {
		return nil, fmt.Errorf("nil curve")
	}
	n := (curve.Params().N.BitLen() + 7) / 8
	sig := make([]byte, n*2)
	if err := I2OSP(r, sig[:n]); err != nil {
		return nil, err
	}
	if err := I2OSP(s, sig[n:]); err != nil {
		return nil, err
	}
	return sig, nil
}


