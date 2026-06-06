package delegationcert

import (
	"fmt"
	"strings"
)

// Curve names the EC curve for a delegated key pair.
type Curve string

const (
	Secp256r1 Curve = "secp256r1"
)

// ParseCurve normalizes config strings to Curve. Only P-256 (ES256) is
// supported for delegated checkpoint keys; KS256 (-65799) is external-only.
func ParseCurve(raw string) (Curve, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	switch trimmed {
	case "", "secp256r1", "p-256", "p256", "r1", "es256":
		return Secp256r1, nil
	default:
		return "", fmt.Errorf("expected secp256r1 (ES256), got %q", raw)
	}
}
