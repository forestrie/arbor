package tests

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	"github.com/forestrie/go-merklelog-datatrails/datatrails"
	"github.com/forestrie/go-merklelog-provider-testing/mmrtesting"
	"github.com/forestrie/go-merklelog-provider-testing/providers"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/stretchr/testify/require"
)

type minioConfig struct {
	Endpoint        string
	Bucket          string
	BearerToken     string // Kept for backward compatibility
	AccessKeyID     string
	SecretAccessKey string
	Region          string
}

func loadMinioConfig() minioConfig {
	endpoint := os.Getenv("R2_MINIO_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:9000"
	}
	bucket := os.Getenv("R2_MINIO_BUCKET")
	if bucket == "" {
		bucket = "ranger-r2-tests"
	}

	// Use MinIO defaults, allow environment variable overrides
	accessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	if accessKeyID == "" {
		accessKeyID = "minioadmin"
	}
	secretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if secretAccessKey == "" {
		secretAccessKey = "minioadmin"
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	return minioConfig{
		Endpoint:        endpoint,
		Bucket:          bucket,
		BearerToken:     os.Getenv("R2_MINIO_BEARER_TOKEN"),
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Region:          region,
	}
}

func ensureMinioAvailable(t *testing.T, cfg minioConfig) {
	t.Helper()

	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	healthURL, err := url.JoinPath(endpoint, "minio/health/live")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		t.Fatalf("failed to build MinIO health request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

type httpDoer struct {
	client *http.Client
}

func (d *httpDoer) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return d.client.Do(req.WithContext(ctx))
}

type MinioEmulator struct {
	client *s3.Client
}

// DeleteLog deletes all stored objects for the given log ID.
//
// NOTE: This intentionally deletes both legacy v1 (datatrails) prefixes and the
// v2 merklelog prefixes (massifs/checkpoints) across all heights. This avoids
// test flakiness when log IDs are deterministically generated across runs.
func (m *MinioEmulator) DeleteLog(logID massifstorage.LogID) {
	if len(logID) == 0 {
		return
	}

	// Legacy v1 prefix (best-effort).
	m.DeleteByStoragePrefix(datatrails.StoragePrefixPath(logID))

	// v2 prefixes (across all heights): list + filter by parsed log id.
	m.DeleteByParsedLogIDPrefix(massifstorage.V2MerklelogMassifsPrefix+"/", logID)
	m.DeleteByParsedLogIDPrefix(massifstorage.V2MerklelogCheckpointsPrefix+"/", logID)
}

func (m *MinioEmulator) DeleteByStoragePrefix(prefix string) {
	if prefix == "" {
		return
	}

	ctx := context.Background()
	continuation := ""
	for {
		res, err := m.client.ListObjects(ctx, prefix, continuation, 1000)
		if err != nil {
			return
		}
		for _, obj := range res.Objects {
			_ = m.client.DeleteObject(ctx, obj.Key)
		}
		if !res.IsTruncated || res.NextContinuationToken == "" {
			break
		}
		continuation = res.NextContinuationToken
	}
}

func (m *MinioEmulator) DeleteByParsedLogIDPrefix(prefix string, logID massifstorage.LogID) {
	if prefix == "" || len(logID) == 0 {
		return
	}

	ctx := context.Background()
	continuation := ""
	for {
		res, err := m.client.ListObjects(ctx, prefix, continuation, 1000)
		if err != nil {
			return
		}
		for _, obj := range res.Objects {
			parsed := massifstorage.ParsePrefixedLogID("tenant/", obj.Key)
			if parsed == nil {
				continue
			}
			if string(parsed) != string(logID) {
				continue
			}
			_ = m.client.DeleteObject(ctx, obj.Key)
		}
		if !res.IsTruncated || res.NextContinuationToken == "" {
			break
		}
		continuation = res.NextContinuationToken
	}
}

type TestContext struct {
	*mmrtesting.TestContext[*MinioEmulator]
	cfg     minioConfig
	baseURL string
	logger  *slog.Logger
	doer    *httpDoer
	testCfg mmrtesting.TestOptions
}

func NewTestContext(t *testing.T, opts ...massifs.Option) *TestContext {
	opts = append([]massifs.Option{mmrtesting.WithDefaults()}, opts...)
	cfg := &mmrtesting.TestOptions{}
	for _, opt := range opts {
		opt(cfg)
	}
	cfg.EnsureDefaults(t)

	minioCfg := loadMinioConfig()
	ensureMinioAvailable(t, minioCfg)

	endpoint := strings.TrimRight(minioCfg.Endpoint, "/")
	bucket := strings.Trim(minioCfg.Bucket, "/")
	baseURL, err := url.JoinPath(endpoint, bucket)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	doer := &httpDoer{client: &http.Client{Timeout: 30 * time.Second}}

	// Use SigV4 signing with MinIO credentials (matches production)
	client, err := s3.NewClientWithCredentials(
		baseURL,
		minioCfg.BearerToken, // Fallback if no credentials
		minioCfg.AccessKeyID,
		minioCfg.SecretAccessKey,
		minioCfg.Region,
		doer,
		logger,
		s3.WithContentSHA256(true), // SigV4 requires this
	)
	require.NoError(t, err)

	emulator := &MinioEmulator{client: client}
	base := mmrtesting.NewTestContext(t, emulator, cfg)

	return &TestContext{
		TestContext: base,
		cfg:         minioCfg,
		baseURL:     baseURL,
		logger:      logger,
		doer:        doer,
		testCfg:     *cfg,
	}
}

func (tc *TestContext) NewBuilder(massifHeight uint8) mmrtesting.LogBuilder {
	// Build a store configured with the requested massifHeight.
	factory, err := merklelog.NewS3FactoryWithCredentials(
		tc.baseURL,
		tc.cfg.BearerToken, // Fallback if no credentials
		tc.cfg.AccessKeyID,
		tc.cfg.SecretAccessKey,
		tc.cfg.Region,
		massifHeight,
		tc.doer,
		tc.logger,
		s3.WithContentSHA256(true), // SigV4 requires this
	)
	require.NoError(tc.T, err)

	store, err := factory.NewStore(nil)
	require.NoError(tc.T, err)

	builder := mmrtesting.LogBuilder{
		LeafGenerator: mmrtesting.LeafGenerator{
			Generator: func(logID massifstorage.LogID, base, i uint64) any {
				return tc.G.GenerateLeafContent(logID, base, i)
			},
			Encoder: func(a any) mmrtesting.AddLeafArgs {
				return tc.G.EncodeLeafForAddition(a)
			},
		},
		// Ensure log cleanup for this test; DeleteLog implementation deletes v1+v2 objects.
		DeleteLog:          tc.DeleteLog,
		SelectLog:          store.SelectLog,
		ObjectReader:       store,
		ObjectWriter:       store,
		ObjectReaderWriter: store,
	}
	return builder
}

func (tc *TestContext) DeleteLog(logID massifstorage.LogID) {
	// Override mmrtesting.TestContext.DeleteLog (which only deletes v1 prefixes)
	// so that ranger integration tests clean up v2 objects too.
	if tc == nil || tc.Emulator == nil {
		return
	}
	tc.Emulator.DeleteLog(logID)
}

func NewBuilderFactory(tc *TestContext) providers.BuilderFactory {
	return func(massifHeight uint8) mmrtesting.LogBuilder {
		return tc.NewBuilder(massifHeight)
	}
}

func (tc *TestContext) GetTestCfg() mmrtesting.TestOptions {
	return tc.testCfg
}
