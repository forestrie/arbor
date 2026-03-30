package delegationcert

import "testing"

func TestParseCurve(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want Curve
	}{
		{"", Secp256k1},
		{"ES256", Secp256r1},
		{"es256k", Secp256k1},
	} {
		c, err := ParseCurve(tc.in)
		if err != nil {
			t.Fatalf("ParseCurve(%q): %v", tc.in, err)
		}
		if c != tc.want {
			t.Fatalf("ParseCurve(%q) = %q, want %q", tc.in, c, tc.want)
		}
	}
	if _, err := ParseCurve("nope"); err == nil {
		t.Fatal("expected error for invalid curve")
	}
}
