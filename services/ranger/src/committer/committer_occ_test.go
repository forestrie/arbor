package committer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog/merklelogtest"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/google/uuid"
)

// TestMassifAppendRequiresUnchangedObject checks the update half of the
// massif write concurrency control: committing an append to an existing
// massif must succeed only if the object is still the one that was read
// (If-Match on the ETag from GetAppendContext). Creating a massif is the
// other half (If-None-Match: *) and already holds.
//
// The Azure store has always enforced this (go-merklelog-azure
// storage/objectheadreplacer.go). The R2 Store.Put used to write appends
// with an empty ETag, so the second of two writers silently replaced the
// first (FOR-656).
//
// Two stores over one client stand in for two rangers on the same log,
// e.g. while the SequencingQueue moves the log between pollers.
func TestMassifAppendRequiresUnchangedObject(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := merklelogtest.NewMemClient()

	// Seed massif 0 so the writes below are updates, not creates.
	logID := uuid.New()
	c := newTestCommitter(t, client)
	if _, err := c.CommitLogGroup(ctx, logID[:], testEntries(1)); err != nil {
		t.Fatalf("seed CommitLogGroup: %v", err)
	}

	openAppend := func() (*merklelog.Store, massifs.MassifContext) {
		t.Helper()
		factory, err := merklelog.NewFactory(client, c.massifHeight, logger)
		if err != nil {
			t.Fatalf("NewFactory: %v", err)
		}
		store, err := factory.NewStore(massifstorage.LogID(logID[:]))
		if err != nil {
			t.Fatalf("NewStore: %v", err)
		}
		if err := store.SelectLog(ctx, massifstorage.LogID(logID[:])); err != nil {
			t.Fatalf("SelectLog: %v", err)
		}
		mc, err := massifs.GetAppendContext(ctx, store, 1, c.massifHeight)
		if err != nil {
			t.Fatalf("GetAppendContext: %v", err)
		}
		if mc.Creating {
			t.Fatalf("append context is creating; the seed did not commit massif 0")
		}
		return store, mc
	}

	// Both writers read the same massif 0, then each appends its own leaf.
	storeA, mcA := openAppend()
	storeB, mcB := openAppend()
	leafA := sha256.Sum256([]byte("writer A"))
	leafB := sha256.Sum256([]byte("writer B"))
	if _, err := mcA.AddIndexedEntry(leafA[:]); err != nil {
		t.Fatalf("A AddIndexedEntry: %v", err)
	}
	if _, err := mcB.AddIndexedEntry(leafB[:]); err != nil {
		t.Fatalf("B AddIndexedEntry: %v", err)
	}

	if err := massifs.CommitContext(ctx, storeA, &mcA); err != nil {
		t.Fatalf("A CommitContext: %v", err)
	}
	wroteA := append([]byte(nil), mcA.Data...)

	errB := massifs.CommitContext(ctx, storeB, &mcB)

	_, mcNow := openAppend()
	switch {
	case errB == nil && bytes.Equal(mcNow.Data, mcB.Data):
		t.Fatalf("B's update replaced A's committed massif: A's leaf is lost " +
			"(the append was written without If-Match)")
	case errB == nil:
		t.Fatalf("B's update succeeded over A's commit")
	case !errors.Is(errB, massifstorage.ErrContentOC):
		t.Errorf("B failed with %v, want a content precondition failure (ErrContentOC)", errB)
	}
	if !bytes.Equal(mcNow.Data, wroteA) {
		t.Errorf("stored massif is not A's committed write")
	}
}
