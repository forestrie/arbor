package storage

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/forestrie/go-merklelog-datatrails/datatrails"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Store provides backend-agnostic implementations of massifs.ObjectReader and ObjectWriter.
type Store struct {
	client ObjectClient
	logger *slog.Logger

	logCaches map[string]*logCache
	selected  *logCache
}

type logCache struct {
	logID       massifstorage.LogID
	writer      *Replacer
	massifs     map[uint32][]byte
	checkpoints map[uint32][]byte
}

// NewStore constructs a reader/writer for the given logID.
func NewStore(client ObjectClient, logID massifstorage.LogID, logger *slog.Logger) (*Store, error) {
	if client == nil {
		return nil, fmt.Errorf("object client is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	store := &Store{
		client:    client,
		logger:    logger,
		logCaches: make(map[string]*logCache),
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

// HasCapability reports supported storage features.
func (s *Store) HasCapability(feature massifstorage.StorageFeature) bool {
	switch feature {
	case massifstorage.OptimisticWrite:
		return s.selected != nil && s.selected.writer != nil
	default:
		return false
	}
}

// HeadIndex fetches the last object index for the given object type.
func (s *Store) HeadIndex(ctx context.Context, otype massifstorage.ObjectType) (uint32, error) {
	cache, err := s.currentLog()
	if err != nil {
		return 0, err
	}

	prefix, err := datatrails.StorageObjectPrefix(cache.logID, otype)
	if err != nil {
		return 0, err
	}

	var continuation string
	var lastKey string
	found := false

	for {
		listResult, err := s.client.ListObjects(ctx, prefix, continuation, 1000)
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

	data, ok := cache.massifs[massifIndex]
	if !ok {
		return nil, false, nil
	}
	return data, true, nil
}

// CheckpointData returns cached checkpoint data if available.
func (s *Store) CheckpointData(massifIndex uint32) ([]byte, bool, error) {
	cache, err := s.currentLog()
	if err != nil {
		return nil, false, err
	}

	data, ok := cache.checkpoints[massifIndex]
	if !ok {
		return nil, false, nil
	}
	return data, true, nil
}

// ObjectPath constructs the storage path for the given object type and massif index.
func (s *Store) ObjectPath(massifIndex uint32, otype massifstorage.ObjectType) (string, error) {
	cache, err := s.currentLog()
	if err != nil {
		return "", err
	}

	prefix, err := datatrails.StorageObjectPrefix(cache.logID, otype)
	if err != nil {
		return "", fmt.Errorf("failed to compute prefix: %w", err)
	}
	return massifstorage.ObjectPath(prefix, cache.logID, massifIndex, otype)
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
			opts.RangeLength = -1
		}
	} else {
		opts.RangeLength = -1
	}

	result, err := s.client.GetObject(ctx, path, opts)
	if err != nil {
		return nil, err
	}

	cache.massifs[massifIndex] = result.Data
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

	cache.checkpoints[massifIndex] = result.Data
	return result.Data, nil
}

// Put delegates to the underlying writer to store massif or checkpoint data.
func (s *Store) Put(
	ctx context.Context,
	massifIndex uint32,
	ty massifstorage.ObjectType,
	data []byte,
	failIfExists bool,
) error {
	cache, err := s.currentLog()
	if err != nil {
		return err
	}
	if err := cache.writer.Put(ctx, massifIndex, ty, data, failIfExists); err != nil {
		return err
	}

	// Update cache after successful write, matching Azure implementation behavior
	switch ty {
	case massifstorage.ObjectMassifData:
		cache.massifs[massifIndex] = data
	case massifstorage.ObjectCheckpoint:
		cache.checkpoints[massifIndex] = data
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

	writer, err := NewReplacer(s.client, logID, s.logger)
	if err != nil {
		return nil, err
	}

	cache := &logCache{
		logID:       append(massifstorage.LogID{}, logID...),
		writer:      writer,
		massifs:     make(map[uint32][]byte),
		checkpoints: make(map[uint32][]byte),
	}
	s.logCaches[key] = cache
	return cache, nil
}

// Errors returned from the underlying ObjectClient are expected to already
// be mapped into massifstorage errors by the backend implementations (S3, R2,
// etc.), so Store does not perform any additional HTTP-specific translation.
