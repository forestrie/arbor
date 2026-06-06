package delegationcert

import "testing"

func TestParseCurve(t *testing.T) {
	cases := []struct {
		in   string
		want Curve
	}{
		{"", Secp256r1},
		{"secp256r1", Secp256r1},
		{"es256", Secp256r1},
		{"P-256", Secp256r1},
	}
	for _, tc := range cases {
		c, err := ParseCurve(tc.in)
		if err != nil {
			t.Fatalf("ParseCurve(%q): %v", tc.in, err)
		}
		if c != tc.want {
			t.Fatalf("ParseCurve(%q) = %q, want %q", tc.in, c, tc.want)
		}
	}
	if _, err := ParseCurve("secp256k1"); err == nil {
		t.Fatal("expected secp256k1 to be rejected")
	}
	if _, err := ParseCurve("nope"); err == nil {
		t.Fatal("expected invalid curve to fail")
	}
}
