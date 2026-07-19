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

// fingerprintDomain separates log fingerprints from every other SHA-256 use.
// The services derive live credentials as plain sha256 of other secrets
// (AWS_SECRET_ACCESS_KEY = sha256(R2_TOKEN) when unset), so a bare
// SHA256Hex of a credential can BE another live credential (FOR-409).
// Fingerprints must never be computable as any credential derivation.
const fingerprintDomain = "forestrie/logredact/fingerprint/v1\x00"

// FingerprintHexLen truncates fingerprints to 16 hex chars (64 bits):
// ample for log correlation, useless as key material.
const FingerprintHexLen = 16

// Fingerprint returns a short, domain-separated identifier for a secret,
// safe to log even when other secrets are derived by hashing this one.
// Returns "" when len(b)==0.
func Fingerprint(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(append([]byte(fingerprintDomain), b...))
	return hex.EncodeToString(sum[:])[:FingerprintHexLen]
}

// StringFingerprint is Fingerprint([]byte(s)).
func StringFingerprint(s string) string {
	return Fingerprint([]byte(s))
}
