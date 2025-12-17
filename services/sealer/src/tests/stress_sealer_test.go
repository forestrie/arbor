//go:build integration
// +build integration

package tests

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	"github.com/forestrie/arbor/services/sealer"
	"github.com/forestrie/go-merklelog/massifs"
	commoncbor "github.com/forestrie/go-merklelog/massifs/cbor"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// This test intentionally races multiple sealer runs against the same log
// while the log advances, to exercise the ETag/If-Match retry logic on
// checkpoints.
func Test_SealerCheckpointLog_racingCheckpointLogs_minio(t *testing.T) {
	minio := loadMinioConfig()
	ensureMinioAvailable(t, minio)

	endpoint := strings.TrimRight(minio.Endpoint, "/")
	bucket := strings.Trim(minio.Bucket, "/")
	baseURL, err := url.JoinPath(endpoint, bucket)
	require.NoError(t, err)

	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	httpClient := sealer.NewHTTPClient(log)

	// Small massif height to roll massifs quickly in a short test.
	const massifHeight uint8 = 4
	const epoch uint32 = 1

	logUUID := uuid.New()
	logID := massifstorage.LogID(logUUID[:])

	s3Client, err := s3.NewClientWithCredentials(
		baseURL,
		minio.BearerToken,
		minio.AccessKeyID,
		minio.SecretAccessKey,
		minio.Region,
		httpClient,
		log,
		s3.WithContentSHA256(true),
	)
	require.NoError(t, err)
	deleteV2LogObjects(t.Context(), s3Client, logID, massifHeight)

	delegationSigner := newFakeDelegationSigner(t)
	t.Cleanup(delegationSigner.Close)

	cfg := sealer.Config{
		DelegationSignerServiceAccountEmail: "integration-test@example.com",
		DelegationSignerURL:                 delegationSigner.URL,
		DelegationKeyCurve:                  "secp256r1",

		R2WriteURL:    baseURL,
		R2WriterToken: minio.BearerToken,

		AWSAccessKeyID:     minio.AccessKeyID,
		AWSSecretAccessKey: minio.SecretAccessKey,
		AWSRegion:          minio.Region,
	}

	// Create a writer store for the log (v2 schema).
	writerFactory, err := merklelog.NewS3FactoryWithCredentials(
		baseURL,
		minio.BearerToken,
		minio.AccessKeyID,
		minio.SecretAccessKey,
		minio.Region,
		massifHeight,
		httpClient,
		log,
		s3.WithContentSHA256(true),
	)
	require.NoError(t, err)
	writerStore, err := writerFactory.NewStore(logID)
	require.NoError(t, err)

	// Round 1: append a couple leaves, then race checkpointing to create the first checkpoint.
	var idTimestamp uint64 = 1
	idTimestamp = appendLeaves(t, writerStore, logID, epoch, massifHeight, idTimestamp, 2)
	size1 := currentMMRSize(t, writerStore)

	runCheckpointLogs(t, cfg, httpClient, log, "test-token", logID, massifHeight, 8)
	assertCheckpointSize(t, baseURL, minio, httpClient, log, logID, massifHeight, 0, size1)

	// Round 2: advance the same massif and race checkpointing to update checkpoint[0].
	idTimestamp = appendLeaves(t, writerStore, logID, epoch, massifHeight, idTimestamp, 2)
	size2 := currentMMRSize(t, writerStore)
	require.Greater(t, size2, size1)

	runCheckpointLogs(t, cfg, httpClient, log, "test-token", logID, massifHeight, 8)
	assertCheckpointSize(t, baseURL, minio, httpClient, log, logID, massifHeight, 0, size2)

	// Round 3: advance across multiple massifs and race checkpointing to seal/catch up.
	// massifHeight=4 => 8 leaves per massif; we are at 4 leaves, add 20 => total 24 => 3 massifs.
	idTimestamp = appendLeaves(t, writerStore, logID, epoch, massifHeight, idTimestamp, 20)
	finalSize := currentMMRSize(t, writerStore)
	require.Greater(t, finalSize, size2)

	runCheckpointLogs(t, cfg, httpClient, log, "test-token", logID, massifHeight, 12)

	// Assert the head checkpoint exists and matches the current head MMR size.
	headMassif := headMassifIndex(t, baseURL, minio, httpClient, log, logID, massifHeight)
	assertCheckpointSize(t, baseURL, minio, httpClient, log, logID, massifHeight, headMassif, finalSize)
}

type minioConfig struct {
	Endpoint        string
	Bucket          string
	BearerToken     string
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
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func deleteV2LogObjects(ctx context.Context, client *s3.Client, logID massifstorage.LogID, massifHeight uint8) {
	if client == nil || len(logID) == 0 || massifHeight == 0 {
		return
	}

	// v2 massifs
	if basePrefix, err := massifstorage.StorageObjectPrefixWithHeight(logID, massifHeight, massifstorage.ObjectPathMassifs); err == nil {
		deleteByPrefix(ctx, client, massifstorage.V2MerklelogMassifsPrefix+"/"+basePrefix)
	}
	// v2 checkpoints
	if basePrefix, err := massifstorage.StorageObjectPrefixWithHeight(logID, massifHeight, massifstorage.ObjectPathCheckpoints); err == nil {
		deleteByPrefix(ctx, client, massifstorage.V2MerklelogCheckpointsPrefix+"/"+basePrefix)
	}
}

func deleteByPrefix(ctx context.Context, client *s3.Client, prefix string) {
	if prefix == "" {
		return
	}
	continuation := ""
	for {
		res, err := client.ListObjects(ctx, prefix, continuation, 1000)
		if err != nil {
			return
		}
		for _, obj := range res.Objects {
			_ = client.DeleteObject(ctx, obj.Key)
		}
		if !res.IsTruncated || res.NextContinuationToken == "" {
			break
		}
		continuation = res.NextContinuationToken
	}
}

func appendLeaves(
	t *testing.T,
	store *merklelog.Store,
	logID massifstorage.LogID,
	epoch uint32,
	massifHeight uint8,
	idTimestamp uint64,
	n int,
) uint64 {
	t.Helper()
	ctx := t.Context()

	appID := []byte("sealer-integration")

	for i := 0; i < n; i++ {
		mc, err := massifs.GetAppendContext(ctx, store, epoch, massifHeight)
		require.NoError(t, err)

		leaf := sha256.Sum256([]byte(fmt.Sprintf("%x/%d", []byte(logID), idTimestamp)))
		_, err = mc.AddHashedLeaf(sha256.New(), idTimestamp, nil, []byte(logID), appID, leaf[:])
		require.NoError(t, err)

		err = massifs.CommitContext(ctx, store, &mc)
		require.NoError(t, err)

		idTimestamp++
	}
	return idTimestamp
}

func currentMMRSize(t *testing.T, store *merklelog.Store) uint64 {
	t.Helper()
	ctx := t.Context()
	mc, err := massifs.GetMassifHeadContext(ctx, store)
	require.NoError(t, err)
	return mc.RangeCount()
}

func runCheckpointLogs(
	t *testing.T,
	cfg sealer.Config,
	httpClient *sealer.HTTPClient,
	logger *slog.Logger,
	delegationAccessToken string,
	logID massifstorage.LogID,
	massifHeight uint8,
	n int,
) {
	t.Helper()
	ctx := t.Context()

	leaseMgr := sealer.NewDelegationLeaseManager(0, 0)
	svc := sealer.SealerService{
		Cfg:          cfg,
		HTTPClient:   httpClient,
		Logger:       logger,
		LeaseManager: leaseMgr,
	}
	batch := sealer.SealerBatch{DelegationAccessToken: delegationAccessToken}

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = sealer.CheckpointLog(
				ctx,
				svc,
				batch,
				logID,
				massifHeight,
			)
		}()
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
}

func headMassifIndex(
	t *testing.T,
	baseURL string,
	minio minioConfig,
	httpClient *sealer.HTTPClient,
	logger *slog.Logger,
	logID massifstorage.LogID,
	massifHeight uint8,
) uint32 {
	t.Helper()
	factory, err := merklelog.NewS3FactoryWithCredentials(
		baseURL,
		minio.BearerToken,
		minio.AccessKeyID,
		minio.SecretAccessKey,
		minio.Region,
		massifHeight,
		httpClient,
		logger,
		s3.WithContentSHA256(true),
	)
	require.NoError(t, err)
	store, err := factory.NewStore(logID)
	require.NoError(t, err)
	head, err := store.HeadIndex(t.Context(), massifstorage.ObjectMassifData)
	require.NoError(t, err)
	return head
}

func assertCheckpointSize(
	t *testing.T,
	baseURL string,
	minio minioConfig,
	httpClient *sealer.HTTPClient,
	logger *slog.Logger,
	logID massifstorage.LogID,
	massifHeight uint8,
	massifIndex uint32,
	expectedMMRSize uint64,
) {
	t.Helper()

	factory, err := merklelog.NewS3FactoryWithCredentials(
		baseURL,
		minio.BearerToken,
		minio.AccessKeyID,
		minio.SecretAccessKey,
		minio.Region,
		massifHeight,
		httpClient,
		logger,
		s3.WithContentSHA256(true),
	)
	require.NoError(t, err)
	store, err := factory.NewStore(logID)
	require.NoError(t, err)

	codec, err := massifs.NewCBORCodec()
	require.NoError(t, err)

	cp, err := massifs.GetCheckpoint(t.Context(), store, codec, massifIndex)
	require.NoError(t, err)

	require.Equal(t, expectedMMRSize, cp.MMRState.MMRSize)
}

func newFakeDelegationSigner(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/delegations" {
			http.NotFound(w, r)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}

		var req map[string]any
		if err := cbor.Unmarshal(body, &req); err != nil {
			http.Error(w, "cbor", http.StatusBadRequest)
			return
		}

		// Extract delegated_pubkey and derive alg.
		delegated, _ := req["delegated_pubkey"].(map[any]any)
		crv, _ := delegated[int64(-1)].(uint64)
		alg := int64(-7) // ES256
		if crv == 8 {
			alg = -47 // ES256K
		}

		// Global (prefix/no-log) request shape should not include log_id/mmr fields.
		issuedAt, _ := req["issued_at"].(uint64)
		expiresAt, _ := req["expires_at"].(uint64)

		// Use go-merklelog deterministic enc/dec options for realism.
		encOpts := commoncbor.NewDeterministicEncOpts()
		encMode, _ := encOpts.EncMode()

		kid := make([]byte, 16)
		for i := range kid {
			kid[i] = byte(i + 1)
		}

		protectedMap := map[int64]any{
			1: alg,
			3: "application/forestrie.delegation+cbor",
			4: kid,
		}
		protectedBytes, _ := encMode.Marshal(protectedMap)

		delegationID := make([]byte, 16)
		copy(delegationID, []byte("delegation-test!"))

		payloadMap := map[int64]any{
			5:  delegated,        // echo back requested key
			6:  map[string]any{}, // constraints
			7:  uint64(1),        // schema_version
			8:  issuedAt,         // issued_at
			9:  expiresAt,        // expires_at
			10: delegationID,     // delegation_id
		}
		payloadBytes, _ := encMode.Marshal(payloadMap)

		sig := make([]byte, 64) // r||s placeholder

		coseArr := []any{protectedBytes, map[any]any{}, payloadBytes, sig}
		respBytes, _ := encMode.Marshal(coseArr)

		w.Header().Set("Content-Type", "application/cose; cose-type=\"cose-sign1\"")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
	}))
}
