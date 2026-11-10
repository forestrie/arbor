package sealer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

const (
	coseAlgES256 int64 = -7
	coseAlgKS256 int64 = -65799
)

// LogSigningKey is a log's root public key, as univocity reports it.
type LogSigningKey struct {
	PublicKeyPEM string // ES256 SPKI PEM (empty for KS256)
	Alg          string // "ES256" | "KS256"
	AlgInt       int64  // COSE alg (-7 | -65799)
	KS256Signer  []byte // 20-byte address when Alg is KS256
}

// logSigningKeyFromAlgKey builds a root key from univocity's opaque (alg,
// key) form: a 20-byte address for KS256, x||y for ES256.
func logSigningKeyFromAlgKey(alg int64, key []byte) (LogSigningKey, error) {
	switch alg {
	case coseAlgKS256:
		if len(key) != 20 {
			return LogSigningKey{}, fmt.Errorf("KS256 trust root key must be 20 bytes, got %d", len(key))
		}
		return LogSigningKey{
			Alg:         "KS256",
			AlgInt:      coseAlgKS256,
			KS256Signer: append([]byte(nil), key...),
		}, nil
	case coseAlgES256:
		if len(key) != 64 {
			return LogSigningKey{}, fmt.Errorf("ES256 trust root key must be 64 bytes, got %d", len(key))
		}
		x, y := key[:32], key[32:]
		pemStr, err := EncodeECDSAPublicKeyPEMFromXY("ES256", x, y)
		if err != nil {
			return LogSigningKey{}, err
		}
		return LogSigningKey{
			PublicKeyPEM: pemStr,
			Alg:          "ES256",
			AlgInt:       coseAlgES256,
		}, nil
	default:
		return LogSigningKey{}, fmt.Errorf("unsupported trust root alg %d", alg)
	}
}

// IsKS256Root reports whether the trust root is a KS256 Ethereum address signer.
func (k LogSigningKey) IsKS256Root() bool {
	return k.AlgInt == coseAlgKS256 || strings.EqualFold(k.Alg, "KS256")
}

// DelegatedCurve returns the curve of the delegated (standing) key.
func (k LogSigningKey) DelegatedCurve() delegationcert.Curve {
	return delegationcert.Secp256r1
}

// EncodeECDSAPublicKeyPEMFromXY builds a PEM-encoded SPKI public key from the
// CBOR-shaped (alg, x, y) root key material. Only ES256 (P-256) is
// supported.
func EncodeECDSAPublicKeyPEMFromXY(alg string, x, y []byte) (string, error) {
	a := strings.ToUpper(strings.TrimSpace(alg))
	var curve elliptic.Curve
	var coordLen int
	switch a {
	case "ES256":
		curve = elliptic.P256()
		coordLen = 32
	default:
		return "", fmt.Errorf("unsupported root key alg %q", alg)
	}
	if len(x) == 0 || len(y) == 0 {
		return "", fmt.Errorf("root public key x/y are empty")
	}
	if len(x) > coordLen || len(y) > coordLen {
		return "", fmt.Errorf(
			"root public key coordinates too large for %s (x=%d y=%d)",
			a, len(x), len(y),
		)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	if !curve.IsOnCurve(pub.X, pub.Y) {
		return "", fmt.Errorf("root public key is not on curve %s", a)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal root public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
