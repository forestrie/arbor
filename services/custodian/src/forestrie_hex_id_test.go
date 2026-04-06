package custodian

import "testing"

func TestNormalizeForestrieHexID32_valid(t *testing.T) {
	want := "6ba7b8109dad11d180b400c04fd430c8"
	for _, in := range []string{
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		"0x6ba7b8109dad11d180b400c04fd430c8",
		" 6BA7B8109DAD11D180B400C04FD430C8 ",
	} {
		got, err := NormalizeForestrieHexID32(in)
		if err != nil || got != want {
			t.Fatalf("in %q: got %q err=%v want %q", in, got, err, want)
		}
	}
}

func TestNormalizeForestrieHexID32_invalid(t *testing.T) {
	for _, in := range []string{"", "abc", "6ba7b810-9dad-11d1-80b4-00c04fd430c"} {
		if _, err := NormalizeForestrieHexID32(in); err == nil {
			t.Fatalf("expected error for %q", in)
		}
	}
}
