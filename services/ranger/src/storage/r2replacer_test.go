package storage

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/google/uuid"
)

type testClient struct {
	client *http.Client
}

func (t *testClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return t.client.Do(req.WithContext(ctx))
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

func newLogID() massifstorage.LogID {
	id := uuid.New()
	return massifstorage.LogID(id[:])
}

func TestReplacerPutSuccess(t *testing.T) {
	logID := newLogID()
	var recorded struct {
		path        string
		ifNoneMatch string
		auth        string
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorded.path = r.URL.Path
		recorded.ifNoneMatch = r.Header.Get("If-None-Match")
		recorded.auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	factory, err := NewFactory(server.URL+"/bucket", "token", 14, &testClient{client: server.Client()}, testLogger())
	if err != nil {
		t.Fatalf("NewFactory: %v", err)
	}

	replacer, err := factory.NewReplacer(logID)
	if err != nil {
		t.Fatalf("NewReplacer: %v", err)
	}

	if err := replacer.Put(context.Background(), 1, massifstorage.ObjectMassifData, []byte("payload"), true); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Construct expected path using v2 format
	massifHeight := uint8(14)
	basePrefix, err := massifstorage.StorageObjectPrefixWithHeight(logID, massifHeight, massifstorage.ObjectMassifData)
	if err != nil {
		t.Fatalf("prefix: %v", err)
	}
	servicePrefix := massifstorage.V2MerklelogMassifsPrefix + "/"
	fullPrefix := servicePrefix + basePrefix
	expectedPath, err := massifstorage.ObjectPath(fullPrefix, logID, 1, massifstorage.ObjectMassifData)
	if err != nil {
		t.Fatalf("object path: %v", err)
	}

	if recorded.path != "/bucket/"+expectedPath {
		t.Fatalf("unexpected path %s, expected %s", recorded.path, "/bucket/"+expectedPath)
	}
	if recorded.ifNoneMatch != "*" {
		t.Fatalf("expected If-None-Match *, got %q", recorded.ifNoneMatch)
	}
	if recorded.auth != "Bearer token" {
		t.Fatalf("unexpected auth header %s", recorded.auth)
	}
}

func TestReplacerPutConflictMapping(t *testing.T) {
	logID := newLogID()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "conflict", http.StatusPreconditionFailed)
	}))
	defer server.Close()

	factory, err := NewFactory(server.URL, "token", 14, &testClient{client: server.Client()}, testLogger())
	if err != nil {
		t.Fatalf("NewFactory: %v", err)
	}

	replacer, err := factory.NewReplacer(logID)
	if err != nil {
		t.Fatalf("NewReplacer: %v", err)
	}

	err = replacer.Put(context.Background(), 1, massifstorage.ObjectCheckpoint, []byte("payload"), true)
	if !errors.Is(err, massifstorage.ErrExistsOC) {
		t.Fatalf("expected ErrExistsOC, got %v", err)
	}
}

func TestReplacerPutNotAvailable(t *testing.T) {
	logID := newLogID()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	factory, err := NewFactory(server.URL, "token", 14, &testClient{client: server.Client()}, testLogger())
	if err != nil {
		t.Fatalf("NewFactory: %v", err)
	}

	replacer, err := factory.NewReplacer(logID)
	if err != nil {
		t.Fatalf("NewReplacer: %v", err)
	}

	err = replacer.Put(context.Background(), 1, massifstorage.ObjectCheckpoint, []byte("payload"), false)
	if !errors.Is(err, massifstorage.ErrNotAvailable) {
		t.Fatalf("expected ErrNotAvailable, got %v", err)
	}
}
