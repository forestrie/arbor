package delegationcert

import (
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// ParseDelegatedPublicKeyFromCBOR decodes CBOR-encoded COSE_Key (EC2) bytes.
func ParseDelegatedPublicKeyFromCBOR(b []byte) (*DelegatedCoseKey, Curve, error) {
	if len(b) == 0 {
		return nil, "", fmt.Errorf("delegated public key is empty")
	}
	var raw map[any]any
	if err := cbor.Unmarshal(b, &raw); err != nil {
		return nil, "", fmt.Errorf("decode delegated public key: %w", err)
	}
	m := make(map[int64]any, len(raw))
	for k, v := range raw {
		ki, ok := asInt64(k)
		if !ok {
			return nil, "", fmt.Errorf("delegated public key: non-integer map key")
		}
		m[ki] = v
	}
	return delegatedCoseKeyFromMap(m)
}

func delegatedCoseKeyFromMap(m map[int64]any) (*DelegatedCoseKey, Curve, error) {
	kty, ok := asInt64(m[1])
	if !ok || kty != CoseKeyTypeEC2 {
		return nil, "", fmt.Errorf("delegated public key: expected kty EC2")
	}
	crv, ok := asInt64(m[-1])
	if !ok {
		return nil, "", fmt.Errorf("delegated public key: missing crv")
	}
	x, ok := asBstr(m[-2])
	if !ok || len(x) != 32 {
		return nil, "", fmt.Errorf("delegated public key: x must be 32 bytes")
	}
	y, ok := asBstr(m[-3])
	if !ok || len(y) != 32 {
		return nil, "", fmt.Errorf("delegated public key: y must be 32 bytes")
	}

	if crv != CoseCurveP256 {
		return nil, "", fmt.Errorf("delegated public key: unsupported crv %d", crv)
	}

	key, err := NewDelegatedCoseKey(Secp256r1, x, y)
	if err != nil {
		return nil, "", err
	}
	return key, Secp256r1, nil
}

// CurveFromAlgorithm maps issuer request algorithm strings to Curve.
func CurveFromAlgorithm(raw string) (Curve, error) {
	switch normalizeAlg(raw) {
	case "ES256":
		return Secp256r1, nil
	default:
		return "", fmt.Errorf("unsupported algorithm %q", raw)
	}
}

func normalizeAlg(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}
