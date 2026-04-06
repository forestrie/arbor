package custodian

import (
	"regexp"
	"strings"
)

// GCP Cloud KMS CryptoKey id: [a-zA-Z0-9_-]{1,63}
const maxKMSCryptoKeyIDLen = 63

var cryptoKeyIDChars = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// normalizeUUIDToHyphenated lowercases, strips hyphens, and re-inserts RFC hyphen
// positions. Returns empty if the string is not 32 hex digits worth of input.
func normalizeUUIDToHyphenated(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	b := make([]rune, 0, 32)
	for _, r := range s {
		if r == '-' {
			continue
		}
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			b = append(b, r)
		} else {
			return ""
		}
	}
	if len(b) != 32 {
		return ""
	}
	u := string(b)
	return u[0:8] + "-" + u[8:12] + "-" + u[12:16] + "-" + u[16:20] + "-" + u[20:32]
}

func stripHyphens(s string) string {
	return strings.ReplaceAll(s, "-", "")
}

func validCryptoKeyID(id string) bool {
	return id != "" && len(id) <= maxKMSCryptoKeyIDLen && cryptoKeyIDChars.MatchString(id)
}

// cryptoKeyShortIDFromLogUUID returns the KMS CryptoKey id: 32 lowercase hex digits
// (optional hyphens and 0x prefix). ok is false if selfLogID is not valid 32-hex.
func cryptoKeyShortIDFromLogUUID(selfLogID string) (shortID string, ok bool) {
	out, err := NormalizeForestrieHexID32(selfLogID)
	if err != nil {
		return "", false
	}
	if !validCryptoKeyID(out) {
		return "", false
	}
	return out, true
}
