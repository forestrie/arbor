package storage

import (
	"fmt"

	"log/slog"

	"github.com/forestrie/arbor/services/ranger/r2"
	"github.com/forestrie/arbor/services/ranger/s3"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Factory constructs merklelog writers for specific logs backed by a
// pluggable object storage client (S3, R2, etc.).
type Factory struct {
	// client is a backend-agnostic ObjectClient (S3, R2, etc.).
	client ObjectClient
	logger *slog.Logger
}

// NewFactory initialises a Factory using the shared S3-compatible REST
// client. It is a convenience alias for NewS3Factory used primarily by tests.
func NewFactory(baseURL, token string, doer s3.HTTPDoer, logger *slog.Logger) (*Factory, error) {
	return NewS3Factory(baseURL, token, doer, logger)
}

// NewS3Factory initialises a Factory backed by an S3-compatible client.
func NewS3Factory(baseURL, token string, doer s3.HTTPDoer, logger *slog.Logger) (*Factory, error) {
	if logger == nil {
		logger = slog.Default()
	}

	s3Client, err := s3.NewClient(baseURL, token, doer, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to build s3 client: %w", err)
	}

	// *s3.Client already satisfies ObjectClient via its method set and the
	// shared storageobjects types.
	return &Factory{
		client: s3Client,
		logger: logger,
	}, nil
}

// NewR2Factory initialises a Factory backed by the Cloudflare R2 HTTP/JSON
// client.
func NewR2Factory(baseURL, token string, doer r2.HTTPDoer, logger *slog.Logger) (*Factory, error) {
	if logger == nil {
		logger = slog.Default()
	}

	r2Client, err := r2.NewClient(baseURL, token, doer, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to build r2 client: %w", err)
	}

	// *r2.Client already satisfies ObjectClient via its method set and the
	// shared storageobjects types.
	return &Factory{
		client: r2Client,
		logger: logger,
	}, nil
}

// NewReplacer returns a massifs.ObjectWriter implementation for the provided logID.
func (f *Factory) NewReplacer(logID massifstorage.LogID) (*Replacer, error) {
	return NewReplacer(f.client, logID, f.logger)
}

// NewStore returns an ObjectReaderWriter implementation for the given logID.
func (f *Factory) NewStore(logID massifstorage.LogID) (*Store, error) {
	return NewStore(f.client, logID, f.logger)
}
