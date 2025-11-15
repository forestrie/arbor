package storage

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"log/slog"

	"github.com/forestrie/arbor/services/ranger/r2"
	"github.com/forestrie/go-merklelog-datatrails/datatrails"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Replacer implements the massifs.ObjectWriter interface using Cloudflare R2.
type Replacer struct {
	client *r2.Client
	logID  massifstorage.LogID
	logger *slog.Logger
}

// NewReplacer builds a Replacer for the provided log ID.
func NewReplacer(client *r2.Client, logID massifstorage.LogID, logger *slog.Logger) (*Replacer, error) {
	if client == nil {
		return nil, fmt.Errorf("r2 client is required")
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

	opts := r2.PutOptions{}
	if failIfExists {
		opts.IfNoneMatch = "*"
	}

	_, err = r.client.PutObject(ctx, objectPath, data, opts)
	if err != nil {
		var apiErr *r2.Error
		if errors.As(err, &apiErr) {
			switch apiErr.StatusCode {
			case http.StatusPreconditionFailed, http.StatusNotModified, http.StatusConflict:
				if failIfExists {
					return massifstorage.ErrExistsOC
				}
				return massifstorage.ErrContentOC
			case http.StatusForbidden, http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusServiceUnavailable:
				return massifstorage.ErrNotAvailable
			default:
				// Leave as formatted error below
			}
		}

		return fmt.Errorf("failed to write object %s: %w", objectPath, err)
	}

	return nil
}
