package custodian

import (
	"fmt"
	"strings"
)

// NormalizeForestrieHexID32 returns exactly 32 lowercase hex digits: trim, strip optional 0x,
// remove hyphens, lowercase. Does not enforce RFC-4122 UUID semantics.
func NormalizeForestrieHexID32(raw string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.TrimPrefix(s, "0x")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return "", fmt.Errorf("forestrie id must be 32 lowercase hex digits")
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", fmt.Errorf("forestrie id must be lowercase hex")
		}
	}
	return s, nil
}
