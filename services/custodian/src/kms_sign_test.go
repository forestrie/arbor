package custodian

import (
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

// TestMaxVersionID: versions compare numerically, not lexically (FOR-584).
func TestMaxVersionID(t *testing.T) {
	const k = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/"
	v := 0
	for _, name := range []string{k + "9", k + "10", k + "2", "bad"} {
		v = maxVersionID(v, name)
	}
	if v != 10 {
		t.Fatalf("max version = %d, want 10", v)
	}
}

func TestKmsErrIsRetiredVersion(t *testing.T) {
	if !kmsErrIsRetiredVersion(status.Error(codes.FailedPrecondition, "disabled")) {
		t.Fatal("FailedPrecondition (disabled version) must be retired")
	}
	if !kmsErrIsRetiredVersion(status.Error(codes.NotFound, "destroyed")) {
		t.Fatal("NotFound (missing version) must be retired")
	}
	if kmsErrIsRetiredVersion(status.Error(codes.Unavailable, "down")) {
		t.Fatal("Unavailable must not be retired")
	}
	if kmsErrIsRetiredVersion(fmt.Errorf("plain")) {
		t.Fatal("non-status error must not be retired")
	}
}
