package storage

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/forestrie/go-merklelog-datatrails/datatrails"
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
		// Backend (S3/R2) is responsible for mapping HTTP/S3 errors into
		// massifstorage errors; we simply wrap with context.
		return fmt.Errorf("failed to write object %s: %w", objectPath, err)
	}

	r.logger.Info("put", "path", objectPath)

	return nil
}
