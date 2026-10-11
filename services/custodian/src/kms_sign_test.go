package custodian

import (
	"errors"
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

// TestKmsMacSignError: FailedPrecondition (version not ENABLED) is a retired
// epoch; NotFound is left ambiguous for the parent-key check (plan-2609-12
// ruling 2); anything else is neither.
func TestKmsMacSignError(t *testing.T) {
	const v = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
	if err := kmsMacSignError(v, status.Error(codes.FailedPrecondition, "disabled")); !errors.Is(err, errDelegateSeedEpochRetired) {
		t.Fatalf("FailedPrecondition: %v, want epoch retired", err)
	}
	err := kmsMacSignError(v, status.Error(codes.NotFound, "missing"))
	if !errors.Is(err, errDelegateSeedVersionNotFound) || errors.Is(err, errDelegateSeedEpochRetired) {
		t.Fatalf("NotFound: %v, want version-not-found only", err)
	}
	for _, e := range []error{status.Error(codes.Unavailable, "down"), fmt.Errorf("plain")} {
		err := kmsMacSignError(v, e)
		if errors.Is(err, errDelegateSeedEpochRetired) || errors.Is(err, errDelegateSeedVersionNotFound) {
			t.Fatalf("%v classified as %v", e, err)
		}
	}
}
