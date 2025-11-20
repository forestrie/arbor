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

	"github.com/forestrie/arbor/services/ranger/r2"
	rangerstorage "github.com/forestrie/arbor/services/ranger/storage"
	"github.com/forestrie/go-merklelog-datatrails/datatrails"
	"github.com/forestrie/go-merklelog-provider-testing/mmrtesting"
	"github.com/forestrie/go-merklelog-provider-testing/providers"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/stretchr/testify/require"
)

type minioConfig struct {
	Endpoint    string
	Bucket      string
	BearerToken string
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
	return minioConfig{
		Endpoint:    endpoint,
		Bucket:      bucket,
		BearerToken: os.Getenv("R2_MINIO_BEARER_TOKEN"),
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
	client *r2.Client
}

func (m *MinioEmulator) DeleteLog(logID massifstorage.LogID) {
	if logID == nil {
		return
	}
	prefix := datatrails.StoragePrefixPath(logID)
	m.DeleteByStoragePrefix(prefix)
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

type TestContext struct {
	*mmrtesting.TestContext[*MinioEmulator]
	cfg     minioConfig
	factory *rangerstorage.Factory
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

	client, err := r2.NewClient(baseURL, minioCfg.BearerToken, doer, logger)
	require.NoError(t, err)

	emulator := &MinioEmulator{client: client}
	base := mmrtesting.NewTestContext(t, emulator, cfg)

	factory, err := rangerstorage.NewFactory(baseURL, minioCfg.BearerToken, doer, logger)
	require.NoError(t, err)

	return &TestContext{
		TestContext: base,
		cfg:         minioCfg,
		factory:     factory,
		doer:        doer,
		testCfg:     *cfg,
	}
}

func (tc *TestContext) NewBuilder() mmrtesting.LogBuilder {
	store, err := tc.factory.NewStore(nil)
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
		DeleteLog:          tc.DeleteLog,
		SelectLog:          store.SelectLog,
		ObjectReader:       store,
		ObjectWriter:       store,
		ObjectReaderWriter: store,
	}
	return builder
}

func NewBuilderFactory(tc *TestContext) providers.BuilderFactory {
	return func() mmrtesting.LogBuilder {
		return tc.NewBuilder()
	}
}

func (tc *TestContext) GetTestCfg() mmrtesting.TestOptions {
	return tc.testCfg
}
