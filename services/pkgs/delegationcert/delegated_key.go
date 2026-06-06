package delegationcert

import "fmt"

// COSE key type and curve labels per RFC 8152.
const (
	CoseKeyTypeEC2 = 2 // kty = EC2
	CoseCurveP256  = 1 // crv for P-256 (secp256r1)
)

// DelegatedCoseKey represents the EC public key being delegated, encoded as a
// COSE_Key (EC2) with integer labels per delegation profile.
type DelegatedCoseKey struct {
	Kty int    // 2 = EC2
	Crv int    // 1 = P-256
	X   []byte // 32 bytes
	Y   []byte // 32 bytes
}

// NewDelegatedCoseKey creates a DelegatedCoseKey from curve and coordinates.
func NewDelegatedCoseKey(curve Curve, x, y []byte) (*DelegatedCoseKey, error) {
	if curve != Secp256r1 {
		return nil, fmt.Errorf("delegated key must use secp256r1 (ES256)")
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("x and y must be 32 bytes each")
	}
	return &DelegatedCoseKey{
		Kty: CoseKeyTypeEC2,
		Crv: CoseCurveP256,
		X:   x,
		Y:   y,
	}, nil
}

// Curve returns the Curve constant for this key.
func (k *DelegatedCoseKey) Curve() Curve {
	return Secp256r1
}

// ToCBORMap returns the COSE_Key as a map[int64]any for CBOR encoding.
// Integer labels per COSE: 1=kty, -1=crv, -2=x, -3=y.
func (k *DelegatedCoseKey) ToCBORMap() map[int64]any {
	return map[int64]any{
		1:  int64(k.Kty), // kty = EC2
		-1: int64(k.Crv), // crv
		-2: k.X,          // x
		-3: k.Y,          // y
	}
}
