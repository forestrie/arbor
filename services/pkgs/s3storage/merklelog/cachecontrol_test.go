package merklelog

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

func newCacheTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

const testMassifHeight uint8 = 4

// massifPayloadWithEntries builds a payload whose length encodes exactly n log
// entries, which is all MassifDataComplete inspects.
func massifPayloadWithEntries(t *testing.T, height uint8, entries uint64) []byte {
	t.Helper()
	size := massifs.PeakStackEnd(height) + entries*massifs.ValueBytes
	data := make([]byte, size)
	// The Replacer validates the height carried in the MassifStart header
	// against the store's configured height before writing.
	data[massifs.MassifStartKeyMassifHeightFirstByte] = height
	return data
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

// recordingClient captures the PutOptions the Replacer derives, so the policy
// is covered end-to-end rather than only as a pure function.
type recordingClient struct {
	lastOpts PutOptions
	lastKey  string
}

func (c *recordingClient) ListObjects(_ context.Context, _, _ string, _ int) (ListPage, error) {
	return ListPage{}, nil
}

func (c *recordingClient) GetObject(_ context.Context, _ string, _ GetOptions) (GetResult, error) {
	return GetResult{}, massifstorage.ErrDoesNotExist
}

func (c *recordingClient) PutObject(_ context.Context, key string, _ []byte, opts PutOptions) (PutResult, error) {
	c.lastKey = key
	c.lastOpts = opts
	return PutResult{ETag: "etag"}, nil
}

func (c *recordingClient) DeleteObject(_ context.Context, _ string) error { return nil }

// The Replacer must attach the derived directive to every write it makes. A
// correct policy that never reaches PutOptions publishes nothing (FOR-302).
func TestReplacerAttachesCacheControl(t *testing.T) {
	full := massifs.TreeCount(testMassifHeight)

	tests := []struct {
		name    string
		ty      massifstorage.ObjectType
		entries uint64
		want    string
	}{
		{
			name:    "complete massif",
			ty:      massifstorage.ObjectMassifData,
			entries: full,
			want:    CacheControlImmutable,
		},
		{
			name:    "head massif",
			ty:      massifstorage.ObjectMassifData,
			entries: full - 1,
			want:    CacheControlNoStore,
		},
		{
			name:    "checkpoint",
			ty:      massifstorage.ObjectCheckpoint,
			entries: full,
			want:    CacheControlNoStore,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &recordingClient{}
			logID := massifstorage.LogID(make([]byte, 16))
			r, err := NewReplacer(client, logID, testMassifHeight, newCacheTestLogger())
			if err != nil {
				t.Fatalf("NewReplacer: %v", err)
			}

			data := massifPayloadWithEntries(t, testMassifHeight, tc.entries)
			if _, err := r.PutWithETag(context.Background(), 0, tc.ty, data, false, ""); err != nil {
				t.Fatalf("PutWithETag: %v", err)
			}

			if client.lastOpts.CacheControl != tc.want {
				t.Fatalf("CacheControl for %s = %q, want %q",
					client.lastKey, client.lastOpts.CacheControl, tc.want)
			}
		})
	}
}
