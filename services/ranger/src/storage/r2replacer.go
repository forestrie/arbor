package storage

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Replacer implements the massifs.ObjectWriter interface using a generic
// ObjectClient backend (S3, R2, etc.).
type Replacer struct {
	client       ObjectClient
	logID        massifstorage.LogID
	massifHeight uint8
	logger       *slog.Logger
}

// NewReplacer builds a Replacer for the provided log ID.
func NewReplacer(client ObjectClient, logID massifstorage.LogID, massifHeight uint8, logger *slog.Logger) (*Replacer, error) {
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
		client:       client,
		logID:        logID,
		massifHeight: massifHeight,
		logger:       logger,
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
	// Use stored massifHeight for v2 path format
	// For massifs, verify massifHeight matches data if available
	if ty == massifstorage.ObjectMassifStart || ty == massifstorage.ObjectMassifData {
		if len(data) >= int(massifs.MassifStartKeyMassifHeightFirstByte+1) {
			dataMassifHeight := data[massifs.MassifStartKeyMassifHeightFirstByte]
			if dataMassifHeight != r.massifHeight {
				return fmt.Errorf("massifHeight mismatch: stored=%d, data=%d", r.massifHeight, dataMassifHeight)
			}
		}
	}

	// Use new v2 path format
	basePrefix, err := massifstorage.StorageObjectPrefixWithHeight(r.logID, r.massifHeight, ty)
	if err != nil {
		return fmt.Errorf("failed to derive storage prefix: %w", err)
	}

	// Add Arbor service prefix: v2/merklelog/massifs/ or v2/merklelog/checkpoints/
	var servicePrefix string
	switch ty {
	case massifstorage.ObjectMassifStart, massifstorage.ObjectMassifData, massifstorage.ObjectPathMassifs:
		servicePrefix = massifstorage.V2MerklelogMassifsPrefix + "/"
	case massifstorage.ObjectCheckpoint, massifstorage.ObjectPathCheckpoints:
		servicePrefix = massifstorage.V2MerklelogCheckpointsPrefix + "/"
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
