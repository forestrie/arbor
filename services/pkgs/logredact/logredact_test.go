package logredact

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestFingerprintIsNotADerivedCredential(t *testing.T) {
	// The services derive AWS_SECRET_ACCESS_KEY = hex(sha256(R2_TOKEN)) when
	// unset. The logged fingerprint of R2_TOKEN must never equal (or prefix)
	// that live credential (FOR-409).
	token := "example-r2-token-value"
	sum := sha256.Sum256([]byte(token))
	derivedCredential := hex.EncodeToString(sum[:])

	fp := StringFingerprint(token)
	if fp == derivedCredential {
		t.Fatalf("fingerprint equals the derived credential")
	}
	if strings.HasPrefix(derivedCredential, fp) {
		t.Fatalf("fingerprint %q is a prefix of the derived credential", fp)
	}
}

func TestFingerprintShape(t *testing.T) {
	fp := StringFingerprint("some-secret")
	if len(fp) != FingerprintHexLen {
		t.Fatalf("fingerprint length = %d, want %d", len(fp), FingerprintHexLen)
	}
	if fp != StringFingerprint("some-secret") {
		t.Fatalf("fingerprint is not stable")
	}
	if fp == StringFingerprint("other-secret") {
		t.Fatalf("distinct secrets collide")
	}
	if StringFingerprint("") != "" {
		t.Fatalf("empty input must fingerprint to empty string")
	}
	if Fingerprint(nil) != "" {
		t.Fatalf("nil input must fingerprint to empty string")
	}
}
