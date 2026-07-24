package merklelog

import (
	"testing"

	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

const testMassifHeight uint8 = 4

// massifPayloadWithEntries builds a payload whose length encodes exactly n log
// entries, which is all MassifDataComplete inspects.
func massifPayloadWithEntries(t *testing.T, height uint8, entries uint64) []byte {
	t.Helper()
	size := massifs.PeakStackEnd(height) + entries*massifs.ValueBytes
	return make([]byte, size)
}

func TestMassifDataComplete(t *testing.T) {
	full := massifs.TreeCount(testMassifHeight)

	tests := []struct {
		name    string
		entries uint64
		want    bool
	}{
		{name: "empty massif is not complete", entries: 0, want: false},
		{name: "one entry short is not complete", entries: full - 1, want: false},
		{name: "exactly full is complete", entries: full, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := massifPayloadWithEntries(t, testMassifHeight, tc.entries)
			if got := MassifDataComplete(data, testMassifHeight); got != tc.want {
				t.Fatalf("MassifDataComplete(%d entries) = %v, want %v", tc.entries, got, tc.want)
			}
		})
	}
}

// A payload too short to be a massif at all must never be published immutable:
// we cannot prove it is complete, so it is not.
func TestMassifDataCompleteRejectsUndersizedPayload(t *testing.T) {
	for _, n := range []int{0, 1, int(massifs.PeakStackEnd(testMassifHeight)) - 1} {
		if MassifDataComplete(make([]byte, n), testMassifHeight) {
			t.Fatalf("undersized payload of %d bytes reported complete", n)
		}
	}
}

func TestCacheControlForObject(t *testing.T) {
	full := massifs.TreeCount(testMassifHeight)
	complete := massifPayloadWithEntries(t, testMassifHeight, full)
	head := massifPayloadWithEntries(t, testMassifHeight, full-1)

	tests := []struct {
		name string
		ty   massifstorage.ObjectType
		data []byte
		want string
	}{
		{
			name: "complete massif is immutable",
			ty:   massifstorage.ObjectMassifData,
			data: complete,
			want: CacheControlImmutable,
		},
		{
			name: "head massif is never cached",
			ty:   massifstorage.ObjectMassifData,
			data: head,
			want: CacheControlNoStore,
		},
		{
			// Sealing runs continuously at the head, so a checkpoint attests
			// only up to its own tree size and is superseded while its massif
			// stays open. Never cached, even alongside a complete massif.
			name: "checkpoint is never cached even when the massif is full",
			ty:   massifstorage.ObjectCheckpoint,
			data: complete,
			want: CacheControlNoStore,
		},
		{
			name: "massif start header is never cached",
			ty:   massifstorage.ObjectMassifStart,
			data: complete,
			want: CacheControlNoStore,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CacheControlForObject(tc.ty, tc.data, testMassifHeight); got != tc.want {
				t.Fatalf("CacheControlForObject = %q, want %q", got, tc.want)
			}
		})
	}
}

// The directive must never be empty: an object published without one is left to
// the CDN's heuristic caching, which is the defect this policy exists to close.
func TestCacheControlForObjectIsAlwaysStated(t *testing.T) {
	types := []massifstorage.ObjectType{
		massifstorage.ObjectMassifData,
		massifstorage.ObjectMassifStart,
		massifstorage.ObjectCheckpoint,
		massifstorage.ObjectPathMassifs,
		massifstorage.ObjectPathCheckpoints,
	}
	for _, ty := range types {
		for _, entries := range []uint64{0, massifs.TreeCount(testMassifHeight)} {
			data := massifPayloadWithEntries(t, testMassifHeight, entries)
			if CacheControlForObject(ty, data, testMassifHeight) == "" {
				t.Fatalf("empty Cache-Control for type %v with %d entries", ty, entries)
			}
		}
	}
}
