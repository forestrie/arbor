package delegationcert

import (
	"fmt"
	"strings"
)

// Curve names the EC curve for a delegated key pair.
type Curve string

const (
	Secp256k1 Curve = "secp256k1"
	Secp256r1 Curve = "secp256r1"
)

// ParseCurve normalizes config strings to Curve.
func ParseCurve(raw string) (Curve, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	switch trimmed {
	case "", "secp256k1", "k1", "es256k":
		return Secp256k1, nil
	case "secp256r1", "p-256", "p256", "r1", "es256":
		return Secp256r1, nil
	default:
		return "", fmt.Errorf("expected secp256k1 or secp256r1, got %q", raw)
	}
}
