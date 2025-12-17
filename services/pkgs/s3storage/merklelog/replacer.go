package merklelog

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Replacer implements conditional object writes for merklelog massifs and checkpoints
// over a backend-agnostic ObjectClient (S3-compatible APIs, etc.).
//
// It supports three write modes:
//   1. Unconditional write/replace: etag=="" and failIfExists==false
//   2. Create-only: etag=="" and failIfExists==true (uses If-None-Match: *)
//   3. Consistent update: etag!= "" and failIfExists==false (uses If-Match: <etag>)
//
// If etag is supplied, failIfExists MUST be false.
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

// Put implements the massifs.ObjectWriter interface using unconditional (or create-only)
// writes. For consistent updates, use PutWithETag.
func (r *Replacer) Put(
	ctx context.Context,
	massifIndex uint32,
	ty massifstorage.ObjectType,
	data []byte,
	failIfExists bool,
) error {
	_, err := r.PutWithETag(ctx, massifIndex, ty, data, failIfExists, "")
	return err
}

// PutWithETag writes the object with explicit conditional semantics.
//
// For consistent updates (If-Match), the caller must supply an ETag obtained from the
// most recent read of the same object. The ETag value is treated as opaque and must
// be passed exactly as returned by the backend (including quotes and/or W/ prefix if present).
func (r *Replacer) PutWithETag(
	ctx context.Context,
	massifIndex uint32,
	ty massifstorage.ObjectType,
	data []byte,
	failIfExists bool,
	etag string,
) (PutResult, error) {
	// Validate massif height if the data contains a MassifStart header.
	if ty == massifstorage.ObjectMassifStart || ty == massifstorage.ObjectMassifData {
		if len(data) >= int(massifs.MassifStartKeyMassifHeightFirstByte+1) {
			dataMassifHeight := data[massifs.MassifStartKeyMassifHeightFirstByte]
			if dataMassifHeight != r.massifHeight {
				return PutResult{}, fmt.Errorf("massifHeight mismatch: stored=%d, data=%d", r.massifHeight, dataMassifHeight)
			}
		}
	}

	if etag != "" && failIfExists {
		return PutResult{}, fmt.Errorf("invalid write options: etag supplied for consistent update but failIfExists=true")
	}

	// Use v2 path format.
	basePrefix, err := massifstorage.StorageObjectPrefixWithHeight(r.logID, r.massifHeight, ty)
	if err != nil {
		return PutResult{}, fmt.Errorf("failed to derive storage prefix: %w", err)
	}

	// Add Arbor service prefix: v2/merklelog/massifs/ or v2/merklelog/checkpoints/
	var servicePrefix string
	switch ty {
	case massifstorage.ObjectMassifStart, massifstorage.ObjectMassifData, massifstorage.ObjectPathMassifs:
		servicePrefix = massifstorage.V2MerklelogMassifsPrefix + "/"
	case massifstorage.ObjectCheckpoint, massifstorage.ObjectPathCheckpoints:
		servicePrefix = massifstorage.V2MerklelogCheckpointsPrefix + "/"
	default:
		return PutResult{}, fmt.Errorf("unsupported object type: %v", ty)
	}

	fullPrefix := servicePrefix + basePrefix
	objectPath, err := massifstorage.ObjectPath(fullPrefix, r.logID, massifIndex, ty)
	if err != nil {
		return PutResult{}, fmt.Errorf("failed to derive object path: %w", err)
	}

	opts := PutOptions{}
	switch {
	case failIfExists:
		// Create-only
		opts.IfNoneMatch = "*"
		opts.FailIfExists = true
	case etag != "":
		// Consistent update
		opts.IfMatch = etag
	default:
		// Unconditional write/replace
	}

	result, err := r.client.PutObject(ctx, objectPath, data, opts)
	if err != nil {
		return PutResult{}, fmt.Errorf("failed to write object %s: %w", objectPath, err)
	}

	r.logger.Info("put", "path", objectPath, "etag", result.ETag, "failIfExists", failIfExists, "hasIfMatch", etag != "")

	return result, nil
}


