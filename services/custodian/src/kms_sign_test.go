package custodian

import "testing"

func TestCryptoKeyVersionNumber(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int64
	}{
		{"projects/p/locations/l/keyRings/k/cryptoKeys/key/cryptoKeyVersions/7", 7},
		{"projects/p/locations/l/keyRings/k/cryptoKeys/key/cryptoKeyVersions/42", 42},
		{"bad", 0},
	} {
		if got := cryptoKeyVersionNumber(tc.name); got != tc.want {
			t.Errorf("%q: got %d want %d", tc.name, got, tc.want)
		}
	}
}
