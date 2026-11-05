package merklelog_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog/merklelogtest"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/google/uuid"
)

// TestPutRefusesMassifUpdateWithoutRead: a massif update must carry If-Match
// on the ETag from a prior read (FOR-656), so an update to a massif this
// store never read is refused rather than written unconditionally.
func TestPutRefusesMassifUpdateWithoutRead(t *testing.T) {
	ctx := context.Background()
	client := merklelogtest.NewMemClient()
	factory, err := merklelog.NewFactory(client, 3, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewFactory: %v", err)
	}
	logID := uuid.New()
	store, err := factory.NewStore(massifstorage.LogID(logID[:]))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.SelectLog(ctx, massifstorage.LogID(logID[:])); err != nil {
		t.Fatalf("SelectLog: %v", err)
	}

	err = store.Put(ctx, 0, massifstorage.ObjectMassifData, []byte{0}, false)
	if err == nil || !strings.Contains(err.Error(), "no ETag") {
		t.Fatalf("Put update without a read = %v, want a no-ETag refusal", err)
	}
	if keys := client.Keys(); len(keys) != 0 {
		t.Errorf("refused update wrote %v", keys)
	}
}
