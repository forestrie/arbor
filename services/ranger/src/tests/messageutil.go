package tests

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/forestrie/arbor/services/ranger"
	"github.com/forestrie/arbor/services/ranger/consumer"
	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/google/uuid"
)

func makeQueueMessage1(
	tc *TestContext,
	logID massifstorage.LogID,
	content []byte,
) consumer.QueueMessage {
	var err error
	t := tc.GetT()
	g := tc.GetG()

	logIDUUID, err := uuid.FromBytes(logID)
	if err != nil {
		t.Fatalf("bad logID: %v", err)
	}

	logIDStr := logIDUUID.String()

	// Compute SHA256 content hash
	shasher := sha256.New()
	_, err = shasher.Write(content)
	require.NoError(t, err)
	contentHash := shasher.Sum(nil)
	contentHashStr := fmt.Sprintf("%x", contentHash)

	// Compute MD5 ETag
	masher := md5.New()
	_, err = masher.Write(content)
	require.NoError(t, err)
	etag := masher.Sum(nil)
	etagStr := fmt.Sprintf("%x", etag)

	notification := consumer.R2Notification{
		Account:   "account",
		Action:    "PutObject",
		Bucket:    "canopy-dev-1-leaves",
		EventTime: g.SinceLastJitter().UTC().Truncate(time.Millisecond).Format(time.RFC3339),
		Object: consumer.R2Object{
			Key:  fmt.Sprintf("logs/%s/leaves/%s", logIDStr, contentHashStr),
			Size: int64(len(content)),
			ETag: etagStr,
		},
	}

	body, err := json.Marshal(notification)
	if err != nil {
		t.Fatalf("marshal notification: %v", err)
	}

	bodyStringJSON, err := json.Marshal(string(body))
	if err != nil {
		t.Fatalf("wrap notification: %v", err)
	}

	raw := json.RawMessage(bodyStringJSON)

	msg := consumer.QueueMessage{
		ID:   "message-id",
		Body: raw,
	}
	return msg
}

func assertNoMessageErrors(t *testing.T, batch *consumer.QueuePullResult) {
	t.Helper()
	for i, msgErr := range batch.Errs {
		require.NoErrorf(t, msgErr, "message %d in batch has error", i)
	}
}

// massifCountForLog uses the same HTTP client stack as the committer/consumer
// to inspect how many massif data objects exist for the given log.
//
// It constructs a ranger storage.Store backed by R2 and returns the number of
// massifs as (headIndex + 1) for ObjectMassifData, or 0 if the log is empty.
func massifCountForLog(
	t *testing.T,
	r2WriteURL string,
	bearerToken string,
	accessKeyID string,
	secretAccessKey string,
	region string,
	massifHeight uint8,
	httpClient *ranger.HTTPClient,
	logger *slog.Logger,
	logID massifstorage.LogID,
) uint32 {
	t.Helper()

	factory, err := merklelog.NewS3FactoryWithCredentials(
		r2WriteURL,
		bearerToken, // Fallback if no credentials
		accessKeyID,
		secretAccessKey,
		region,
		massifHeight,
		httpClient,
		logger,
		s3.WithContentSHA256(true), // SigV4 requires this
	)
	require.NoError(t, err)

	store, err := factory.NewStore(nil)
	require.NoError(t, err)

	ctx := t.Context()

	err = store.SelectLog(ctx, logID)
	require.NoError(t, err)

	head, err := store.HeadIndex(ctx, massifstorage.ObjectMassifData)
	if errors.Is(err, massifstorage.ErrLogEmpty) {
		return 0
	}
	require.NoError(t, err)

	return head + 1
}

// assertMassifCount wraps massifCountForLog with an assertion, for convenient
// reuse across tests.
func assertMassifCount(
	t *testing.T,
	r2WriteURL string,
	bearerToken string,
	accessKeyID string,
	secretAccessKey string,
	region string,
	massifHeight uint8,
	httpClient *ranger.HTTPClient,
	logger *slog.Logger,
	logID massifstorage.LogID,
	expected uint32,
) {
	t.Helper()

	actual := massifCountForLog(
		t,
		r2WriteURL,
		bearerToken,
		accessKeyID,
		secretAccessKey,
		region,
		massifHeight,
		httpClient,
		logger,
		logID,
	)

	if actual != expected {
		// Instrumentation: list massif objects directly from R2 to
		// confirm ListObjects is returning the massif blobs we expect.
		listMassifObjectsForLog(
			t,
			r2WriteURL,
			bearerToken,
			accessKeyID,
			secretAccessKey,
			region,
			massifHeight,
			httpClient,
			logger,
			logID,
		)
	}

	require.Equalf(t, expected, actual, "unexpected massif count for log")
}

// listMassifObjectsForLog uses the R2 client directly to list massif data
// objects for a given log and logs their keys and derived indices.
func listMassifObjectsForLog(
	t *testing.T,
	r2WriteURL string,
	bearerToken string,
	accessKeyID string,
	secretAccessKey string,
	region string,
	massifHeight uint8,
	httpClient *ranger.HTTPClient,
	logger *slog.Logger,
	logID massifstorage.LogID,
) []string {
	t.Helper()

	client, err := s3.NewClientWithCredentials(
		r2WriteURL,
		bearerToken, // Fallback if no credentials
		accessKeyID,
		secretAccessKey,
		region,
		httpClient,
		logger,
		s3.WithContentSHA256(true), // SigV4 requires this
	)
	require.NoError(t, err)

	basePrefix, err := massifstorage.StorageObjectPrefixWithHeight(
		logID,
		massifHeight,
		massifstorage.ObjectPathMassifs,
	)
	require.NoError(t, err)

	prefix := massifstorage.V2MerklelogMassifsPrefix + "/" + basePrefix

	ctx := t.Context()
	var keys []string
	continuation := ""
	for {
		res, err := client.ListObjects(ctx, prefix, continuation, 1000)
		require.NoError(t, err)

		for _, obj := range res.Objects {
			keys = append(keys, obj.Key)
		}
		if !res.IsTruncated || res.NextContinuationToken == "" {
			break
		}
		continuation = res.NextContinuationToken
	}

	var indices []uint32
	for _, key := range keys {
		idx, err := massifstorage.GetObjectIndex(key, massifstorage.ObjectMassifData)
		if err != nil {
			t.Logf("massif object key=%q: failed to parse index: %v", key, err)
			continue
		}
		indices = append(indices, idx)
	}

	t.Logf(
		"massif objects for log (prefix=%q): keys=%v indices=%v",
		prefix,
		keys,
		indices,
	)

	return keys
}
