package storage

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/forestrie/go-merklelog-datatrails/datatrails"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Replacer implements the massifs.ObjectWriter interface using a generic
// ObjectClient backend (S3, R2, etc.).
type Replacer struct {
	client ObjectClient
	logID  massifstorage.LogID
	logger *slog.Logger
}

// NewReplacer builds a Replacer for the provided log ID.
func NewReplacer(client ObjectClient, logID massifstorage.LogID, logger *slog.Logger) (*Replacer, error) {
	if client == nil {
		return nil, fmt.Errorf("object client is required")
	}
	if len(logID) == 0 {
		return nil, fmt.Errorf("logID is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Replacer{
		client: client,
		logID:  logID,
		logger: logger,
	}, nil
}

// Put uploads massif data or checkpoints to R2.
func (r *Replacer) Put(
	ctx context.Context,
	massifIndex uint32,
	ty massifstorage.ObjectType,
	data []byte,
	failIfExists bool,
) error {
	var massifHeight uint8
	var err error

	// Extract massifHeight from data based on object type
	switch ty {
	case massifstorage.ObjectMassifStart, massifstorage.ObjectMassifData:
		// Extract massifHeight from MassifStart header (byte 27)
		if len(data) < int(massifs.MassifStartKeyMassifHeightFirstByte+1) {
			return fmt.Errorf("massif data too short to read MassifHeight")
		}
		massifHeight = data[massifs.MassifStartKeyMassifHeightFirstByte]
	case massifstorage.ObjectCheckpoint:
		// For checkpoints, we need to read the associated massif to get massifHeight
		// For now, fall back to old format - this will be improved when we have
		// massif context available
		prefix, err := datatrails.StorageObjectPrefix(r.logID, ty)
		if err != nil {
			return fmt.Errorf("failed to derive storage prefix: %w", err)
		}
		objectPath, err := massifstorage.ObjectPath(prefix, r.logID, massifIndex, ty)
		if err != nil {
			return fmt.Errorf("failed to derive object path: %w", err)
		}

		opts := PutOptions{}
		if failIfExists {
			opts.IfNoneMatch = "*"
			opts.FailIfExists = true
		}

		if _, err = r.client.PutObject(ctx, objectPath, data, opts); err != nil {
			return fmt.Errorf("failed to write object %s: %w", objectPath, err)
		}

		r.logger.Info("put", "path", objectPath)
		return nil
	default:
		return fmt.Errorf("unsupported object type: %v", ty)
	}

	// Use new v2 path format for massifs
	basePrefix, err := datatrails.StorageObjectPrefixWithHeight(r.logID, massifHeight, ty)
	if err != nil {
		return fmt.Errorf("failed to derive storage prefix: %w", err)
	}

	// Add Arbor service prefix: v2/merklelog/massifs/ or v2/merklelog/checkpoints/
	var servicePrefix string
	switch ty {
	case massifstorage.ObjectMassifStart, massifstorage.ObjectMassifData, massifstorage.ObjectPathMassifs:
		servicePrefix = datatrails.V2MerklelogMassifsPrefix + "/"
	case massifstorage.ObjectCheckpoint, massifstorage.ObjectPathCheckpoints:
		servicePrefix = datatrails.V2MerklelogCheckpointsPrefix + "/"
	default:
		return fmt.Errorf("unsupported object type: %v", ty)
	}

	// Combine service prefix with base format
	fullPrefix := servicePrefix + basePrefix

	objectPath, err := massifstorage.ObjectPath(fullPrefix, r.logID, massifIndex, ty)
	if err != nil {
		return fmt.Errorf("failed to derive object path: %w", err)
	}

	opts := PutOptions{}
	if failIfExists {
		opts.IfNoneMatch = "*"
		opts.FailIfExists = true
	}

	if _, err = r.client.PutObject(ctx, objectPath, data, opts); err != nil {
		// Backend (S3/R2) is responsible for mapping HTTP/S3 errors into
		// massifstorage errors; we simply wrap with context.
		return fmt.Errorf("failed to write object %s: %w", objectPath, err)
	}

	r.logger.Info("put", "path", objectPath)

	return nil
}
