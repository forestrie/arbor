package custodian

import "testing"

func TestCryptoKeyShortIDFromLogUUID_valid(t *testing.T) {
	self := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	want := "6ba7b8109dad11d180b400c04fd430c8"
	got, ok := cryptoKeyShortIDFromLogUUID(self)
	if !ok || got != want {
		t.Fatalf("got %q ok=%v want %q true", got, ok, want)
	}
}

func TestCryptoKeyShortIDFromLogUUID_empty(t *testing.T) {
	if _, ok := cryptoKeyShortIDFromLogUUID(""); ok {
		t.Fatal("expected false")
	}
}

func TestCryptoKeyShortIDFromLogUUID_invalid(t *testing.T) {
	if _, ok := cryptoKeyShortIDFromLogUUID("not-a-uuid"); ok {
		t.Fatal("expected false")
	}
	if _, ok := cryptoKeyShortIDFromLogUUID("6ba7b810-9dad-11d1-80b4-00c04fd430"); ok {
		t.Fatal("expected false for truncated")
	}
}

func TestNormalizeUUIDToHyphenated(t *testing.T) {
	if g, w := normalizeUUIDToHyphenated("550E8400E29B41D4A716446655440000"), "550e8400-e29b-41d4-a716-446655440000"; g != w {
		t.Fatalf("got %q want %q", g, w)
	}
	if normalizeUUIDToHyphenated("bad") != "" {
		t.Fatal("expected empty")
	}
}
