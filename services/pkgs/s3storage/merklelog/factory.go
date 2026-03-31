package merklelog

import (
	"fmt"
	"log/slog"

	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Factory constructs merklelog stores for specific logs backed by a pluggable
// S3-compatible object storage client (Cloudflare R2 via S3 API, MinIO, AWS S3, etc.).
type Factory struct {
	client       ObjectClient
	logger       *slog.Logger
	massifHeight uint8
}

// NewS3Factory initialises a Factory backed by an S3-compatible client.
// By default, x-amz-content-sha256 header and cloudflareCompat mode are enabled
// (required for Cloudflare R2).
//
// If AWS credentials are provided, use NewS3FactoryWithCredentials.
func NewS3Factory(baseURL, token string, massifHeight uint8, doer s3.HTTPDoer, logger *slog.Logger, opts ...s3.ClientOption) (*Factory, error) {
	return NewS3FactoryWithCredentials(baseURL, token, "", "", "", massifHeight, doer, logger, opts...)
}

// NewS3FactoryWithCredentials initialises a Factory backed by an S3-compatible
// client with AWS credentials.
//
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

// NewFactory constructs a Factory from a caller-supplied ObjectClient.
func NewFactory(client ObjectClient, massifHeight uint8, logger *slog.Logger) (*Factory, error) {
	if client == nil {
		return nil, fmt.Errorf("object client is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Factory{
		client:       client,
		logger:       logger,
		massifHeight: massifHeight,
	}, nil
}

// NewStore returns an ObjectReaderWriter implementation for the given logID.
func (f *Factory) NewStore(logID massifstorage.LogID) (*Store, error) {
	return NewStore(f.client, logID, f.massifHeight, f.logger)
}
