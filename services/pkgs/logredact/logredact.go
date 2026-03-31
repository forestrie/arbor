// Package logredact provides stable SHA-256 hex digests for logs and errors
// without printing raw credentials or response bodies.
package logredact

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Hex returns lowercase hex-encoded SHA-256 of b, or "" when len(b)==0.
func SHA256Hex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// StringSHA256Hex is SHA256Hex([]byte(s)).
func StringSHA256Hex(s string) string {
	return SHA256Hex([]byte(s))
}
