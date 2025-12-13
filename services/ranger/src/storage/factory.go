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
	client       ObjectClient
	logger       *slog.Logger
	massifHeight uint8
}

// NewFactory initialises a Factory using the shared S3-compatible REST
// client. It is a convenience alias for NewS3Factory used primarily by tests.
// For MinIO compatibility, use s3.WithContentSHA256(false) and s3.WithCloudflareCompat(false) options.
func NewFactory(baseURL, token string, massifHeight uint8, doer s3.HTTPDoer, logger *slog.Logger, opts ...s3.ClientOption) (*Factory, error) {
	return NewS3Factory(baseURL, token, massifHeight, doer, logger, opts...)
}

// NewS3Factory initialises a Factory backed by an S3-compatible client.
// By default, x-amz-content-sha256 header and cloudflareCompat mode are enabled (required for Cloudflare R2).
// Use s3.WithContentSHA256(false) and s3.WithCloudflareCompat(false) options to disable them for S3-compatible backends that don't require them.
// If AWS credentials are provided, SigV4 signing will be used instead of bearer token authentication.
func NewS3Factory(baseURL, token string, massifHeight uint8, doer s3.HTTPDoer, logger *slog.Logger, opts ...s3.ClientOption) (*Factory, error) {
	return NewS3FactoryWithCredentials(baseURL, token, "", "", "", massifHeight, doer, logger, opts...)
}

// NewS3FactoryWithCredentials initialises a Factory backed by an S3-compatible client with AWS credentials.
// If accessKeyID and secretAccessKey are provided, SigV4 signing will be used.
// Otherwise, bearer token authentication will be used.
func NewS3FactoryWithCredentials(baseURL, token, accessKeyID, secretAccessKey, region string, massifHeight uint8, doer s3.HTTPDoer, logger *slog.Logger, opts ...s3.ClientOption) (*Factory, error) {
	if logger == nil {
		logger = slog.Default()
	}

	s3Client, err := s3.NewClientWithCredentials(baseURL, token, accessKeyID, secretAccessKey, region, doer, logger, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to build s3 client: %w", err)
	}

	// *s3.Client already satisfies ObjectClient via its method set and the
	// shared storageobjects types.
	return &Factory{
		client:       s3Client,
		logger:       logger,
		massifHeight: massifHeight,
	}, nil
}

// NewR2Factory initialises a Factory backed by the Cloudflare R2 HTTP/JSON
// client.
func NewR2Factory(baseURL, token string, massifHeight uint8, doer r2.HTTPDoer, logger *slog.Logger) (*Factory, error) {
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
		client:       r2Client,
		logger:       logger,
		massifHeight: massifHeight,
	}, nil
}

// NewReplacer returns a massifs.ObjectWriter implementation for the provided logID.
func (f *Factory) NewReplacer(logID massifstorage.LogID) (*Replacer, error) {
	return NewReplacer(f.client, logID, f.massifHeight, f.logger)
}

// NewStore returns an ObjectReaderWriter implementation for the given logID.
func (f *Factory) NewStore(logID massifstorage.LogID) (*Store, error) {
	return NewStore(f.client, logID, f.massifHeight, f.logger)
}
