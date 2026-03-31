package merklelog

import (
	"context"
	"fmt"
	"log/slog"

	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Store provides backend-agnostic implementations of massifs.ObjectReader and massifs.ObjectWriter.
// It is bound to a specific massifHeight for v2 path formatting.
type Store struct {
	client       ObjectClient
	logger       *slog.Logger
	massifHeight uint8

	logCaches map[string]*logCache
	selected  *logCache
}

type cachedObject struct {
	data []byte
	etag string
}

type logCache struct {
	logID       massifstorage.LogID
	writer      *Replacer
	massifs     map[uint32]cachedObject
	checkpoints map[uint32]cachedObject
}

// NewStore constructs a reader/writer for the given logID.
// All Store instances are bound to a specific massifHeight for v2 path format.
func NewStore(client ObjectClient, logID massifstorage.LogID, massifHeight uint8, logger *slog.Logger) (*Store, error) {
	if client == nil {
		return nil, fmt.Errorf("object client is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	store := &Store{
		client:       client,
		logger:       logger,
		massifHeight: massifHeight,
		logCaches:    make(map[string]*logCache),
	}

	if len(logID) != 0 {
		if err := store.SelectLog(context.Background(), logID); err != nil {
			return nil, err
		}
	}

	return store, nil
}

// SelectLog selects (or creates) the cache for the provided log ID.
func (s *Store) SelectLog(ctx context.Context, logID massifstorage.LogID) error {
	if len(logID) == 0 {
		return massifstorage.ErrLogNotSelected
	}

	cache, err := s.ensureLog(logID)
	if err != nil {
		return err
	}
	s.selected = cache
	return nil
}

// HeadIndex fetches the last object index for the given object type.
// Uses the v2 path format with the massifHeight stored in the Store instance.
func (s *Store) HeadIndex(ctx context.Context, otype massifstorage.ObjectType) (uint32, error) {
	cache, err := s.currentLog()
	if err != nil {
		return 0, err
	}

	// Get base prefix from core function using stored massifHeight.
	basePrefix, err := massifstorage.StorageObjectPrefixWithHeight(cache.logID, s.massifHeight, otype)
	if err != nil {
		return 0, err
	}

	// Add Arbor service prefix.
	var servicePrefix string
	switch otype {
	case massifstorage.ObjectMassifStart, massifstorage.ObjectMassifData, massifstorage.ObjectPathMassifs:
		servicePrefix = massifstorage.V2MerklelogMassifsPrefix + "/"
	case massifstorage.ObjectCheckpoint, massifstorage.ObjectPathCheckpoints:
		servicePrefix = massifstorage.V2MerklelogCheckpointsPrefix + "/"
	default:
		return 0, fmt.Errorf("unsupported object type: %v", otype)
	}

	fullPrefix := servicePrefix + basePrefix

	var continuation string
	var lastKey string
	found := false

	for {
		listResult, err := s.client.ListObjects(ctx, fullPrefix, continuation, 1000)
		if err != nil {
			return 0, err
		}

		if len(listResult.Objects) > 0 {
			lastKey = listResult.Objects[len(listResult.Objects)-1].Key
			found = true
		}

		if !listResult.IsTruncated || listResult.NextContinuationToken == "" {
			break
		}
		continuation = listResult.NextContinuationToken
	}

	if !found {
		return 0, massifstorage.ErrLogEmpty
	}

	index, err := massifstorage.GetObjectIndex(lastKey, otype)
	if err != nil {
		return 0, err
	}
	return index, nil
}

// MassifData returns cached massif data if previously read.
func (s *Store) MassifData(massifIndex uint32) ([]byte, bool, error) {
	cache, err := s.currentLog()
	if err != nil {
		return nil, false, err
	}

	obj, ok := cache.massifs[massifIndex]
	if !ok {
		return nil, false, nil
	}
	return obj.data, true, nil
}

// CheckpointData returns cached checkpoint data if available.
func (s *Store) CheckpointData(massifIndex uint32) ([]byte, bool, error) {
	cache, err := s.currentLog()
	if err != nil {
		return nil, false, err
	}

	obj, ok := cache.checkpoints[massifIndex]
	if !ok {
		return nil, false, nil
	}
	return obj.data, true, nil
}

// MassifETag returns the cached ETag for a massif object if present.
func (s *Store) MassifETag(massifIndex uint32) (string, bool, error) {
	cache, err := s.currentLog()
	if err != nil {
		return "", false, err
	}
	obj, ok := cache.massifs[massifIndex]
	if !ok {
		return "", false, nil
	}
	return obj.etag, true, nil
}

// CheckpointETag returns the cached ETag for a checkpoint object if present.
func (s *Store) CheckpointETag(massifIndex uint32) (string, bool, error) {
	cache, err := s.currentLog()
	if err != nil {
		return "", false, err
	}
	obj, ok := cache.checkpoints[massifIndex]
	if !ok {
		return "", false, nil
	}
	return obj.etag, true, nil
}

// ObjectPath constructs the storage path for the given object type and massif index.
// Uses the v2 path format with the massifHeight stored in the Store instance.
func (s *Store) ObjectPath(massifIndex uint32, otype massifstorage.ObjectType) (string, error) {
	cache, err := s.currentLog()
	if err != nil {
		return "", err
	}

	basePrefix, err := massifstorage.StorageObjectPrefixWithHeight(cache.logID, s.massifHeight, otype)
	if err != nil {
		return "", fmt.Errorf("failed to compute prefix: %w", err)
	}

	var servicePrefix string
	switch otype {
	case massifstorage.ObjectMassifStart, massifstorage.ObjectMassifData, massifstorage.ObjectPathMassifs:
		servicePrefix = massifstorage.V2MerklelogMassifsPrefix + "/"
	case massifstorage.ObjectCheckpoint, massifstorage.ObjectPathCheckpoints:
		servicePrefix = massifstorage.V2MerklelogCheckpointsPrefix + "/"
	default:
		return "", fmt.Errorf("unsupported object type: %v", otype)
	}

	fullPrefix := servicePrefix + basePrefix
	return massifstorage.ObjectPath(fullPrefix, cache.logID, massifIndex, otype)
}

// MassifReadN reads up to n bytes (or the entire blob if n < 0) from the massif data object.
func (s *Store) MassifReadN(ctx context.Context, massifIndex uint32, n int) ([]byte, error) {
	cache, err := s.currentLog()
	if err != nil {
		return nil, err
	}

	path, err := s.ObjectPath(massifIndex, massifstorage.ObjectMassifData)
	if err != nil {
		return nil, err
	}

	opts := GetOptions{}
	if n >= 0 {
		opts.RangeStart = 0
		opts.RangeLength = int64(n)
		if n == 0 {
			// Preserve ranger behavior: treat 0 as "read all" rather than 1 byte.
			opts.RangeLength = -1
		}
	} else {
		opts.RangeLength = -1
	}

	result, err := s.client.GetObject(ctx, path, opts)
	if err != nil {
		return nil, err
	}

	cache.massifs[massifIndex] = cachedObject{data: result.Data, etag: result.ETag}
	return result.Data, nil
}

// CheckpointRead reads the entire checkpoint object for the provided massif.
func (s *Store) CheckpointRead(ctx context.Context, massifIndex uint32) ([]byte, error) {
	cache, err := s.currentLog()
	if err != nil {
		return nil, err
	}

	path, err := s.ObjectPath(massifIndex, massifstorage.ObjectCheckpoint)
	if err != nil {
		return nil, err
	}

	result, err := s.client.GetObject(ctx, path, GetOptions{RangeLength: -1})
	if err != nil {
		return nil, err
	}

	cache.checkpoints[massifIndex] = cachedObject{data: result.Data, etag: result.ETag}
	return result.Data, nil
}

// Put implements massifs.ObjectWriter using unconditional (or create-only) writes.
// For consistent updates (If-Match), use PutWithETag.
func (s *Store) Put(
	ctx context.Context,
	massifIndex uint32,
	ty massifstorage.ObjectType,
	data []byte,
	failIfExists bool,
) error {
	return s.PutWithETag(ctx, massifIndex, ty, data, failIfExists, "")
}

// PutWithETag writes the object with explicit conditional semantics.
//
// This method delegates to the underlying ObjectClient and updates the Store cache
// (data + ETag) on success.
func (s *Store) PutWithETag(
	ctx context.Context,
	massifIndex uint32,
	ty massifstorage.ObjectType,
	data []byte,
	failIfExists bool,
	etag string,
) error {
	cache, err := s.currentLog()
	if err != nil {
		return err
	}
	if cache.writer == nil {
		return fmt.Errorf("writer not initialized")
	}

	result, err := cache.writer.PutWithETag(ctx, massifIndex, ty, data, failIfExists, etag)
	if err != nil {
		return err
	}

	switch ty {
	case massifstorage.ObjectMassifData:
		cache.massifs[massifIndex] = cachedObject{data: data, etag: result.ETag}
	case massifstorage.ObjectCheckpoint:
		cache.checkpoints[massifIndex] = cachedObject{data: data, etag: result.ETag}
	}

	return nil
}

func (s *Store) currentLog() (*logCache, error) {
	if s.selected == nil {
		return nil, massifstorage.ErrLogNotSelected
	}
	return s.selected, nil
}

func (s *Store) ensureLog(logID massifstorage.LogID) (*logCache, error) {
	key := string(logID)
	if cache, ok := s.logCaches[key]; ok {
		return cache, nil
	}

	writer, err := NewReplacer(s.client, logID, s.massifHeight, s.logger)
	if err != nil {
		return nil, err
	}

	cache := &logCache{
		logID:       append(massifstorage.LogID{}, logID...),
		writer:      writer,
		massifs:     make(map[uint32]cachedObject),
		checkpoints: make(map[uint32]cachedObject),
	}
	s.logCaches[key] = cache
	return cache, nil
}
