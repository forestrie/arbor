//go:build integration
// +build integration

package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	"github.com/forestrie/arbor/services/sealer"
	"github.com/forestrie/go-merklelog/massifs"
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

	fakeCustodian := newFakeCustodian(t)
	t.Cleanup(fakeCustodian.Close)

	cfg := sealer.Config{
		TrustRootURL:          fakeCustodian.URL,
		DelegationIssuerURL:   fakeCustodian.URL,
		DelegationIssuerToken: "test-custodian-token",
		CustodianURL:          fakeCustodian.URL,
		CustodianAppToken:     "test-custodian-token",
		DelegationKeyCurve:    "secp256r1",

		R2URL: baseURL,

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
	_ string, // unused, was delegation access token
	logID massifstorage.LogID,
	massifHeight uint8,
	n int,
) {
	t.Helper()
	ctx := t.Context()

	leaseMgr := sealer.NewDelegationLeaseManager(
		&sealer.CustodianPublicTrustRootClient{
			BaseURL:    cfg.TrustRootURL,
			HTTPClient: httpClient,
		},
		&sealer.HTTPDelegationIssuer{
			BaseURL:    cfg.DelegationIssuerURL,
			Token:      cfg.DelegationIssuerToken,
			HTTPClient: httpClient,
		},
		0,
		0,
	)
	svc := sealer.SealerService{
		Cfg:          cfg,
		HTTPClient:   httpClient,
		Logger:       logger,
		LeaseManager: leaseMgr,
	}

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

// fakeCustodianState holds ephemeral key pair for the fake custodian to use.
type fakeCustodianState struct {
	privateKey *ecdsa.PrivateKey
}

func newFakeCustodian(t *testing.T) *httptest.Server {
	t.Helper()

	// Generate a P-256 key for all log key requests (tests use secp256r1)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	state := &fakeCustodianState{privateKey: priv}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Match GET /api/keys/<logIdHex>/public - return public key as CBOR
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/public") {
			// Return the custody key in PEM format via CBOR
			pubKeyDER, err := x509.MarshalPKIXPublicKey(&state.privateKey.PublicKey)
			if err != nil {
				http.Error(w, "marshal pub", http.StatusInternalServerError)
				return
			}
			pubKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubKeyDER,
			})

			resp := sealer.CustodianPublicKeyResponse{
				PublicKey: string(pubKeyPEM),
				Alg:       "ES256",
			}
			respBytes, _ := cbor.Marshal(resp)
			w.Header().Set("Content-Type", "application/cbor")
			_, _ = w.Write(respBytes)
			return
		}

		// POST /api/delegations — issue delegation lease (CBOR)
		if r.Method == http.MethodPost && r.URL.Path == "/api/delegations" {
			body, err := io.ReadAll(io.LimitReader(r.Body, 256*1024))
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			var req delegationcert.DelegationIssueRequest
			if err := cbor.Unmarshal(body, &req); err != nil {
				http.Error(w, "cbor unmarshal", http.StatusBadRequest)
				return
			}
			delegatedKey, curve, err := delegationcert.ParseDelegatedPublicKeyFromCBOR(req.DelegatedPublicKey)
			if err != nil {
				http.Error(w, "delegated key", http.StatusBadRequest)
				return
			}
			kid, err := fakeKidFromECDSAPublicKey(&state.privateKey.PublicKey)
			if err != nil {
				http.Error(w, "kid", http.StatusInternalServerError)
				return
			}
			logIdHex, err := fakeLogIDHexFromWire(req.LogID)
			if err != nil {
				http.Error(w, "log id", http.StatusBadRequest)
				return
			}
			issuedAt := uint64(time.Now().Unix())
			expiresAt := issuedAt + req.RequestedTTLSeconds
			if expiresAt == issuedAt {
				expiresAt = issuedAt + uint64((60 * time.Minute).Seconds())
			}
			delegationID := make([]byte, 16)
			if len(req.RequestID) >= 16 {
				copy(delegationID, req.RequestID[:16])
			} else {
				_, _ = rand.Read(delegationID)
			}
			tbs, err := delegationcert.BuildDelegationToBeSigned(curve, kid, delegationcert.DelegationInput{
				LogID:        logIdHex,
				MmrStart:     req.MMRStart,
				MmrEnd:       req.MMREnd,
				DelegatedKey: delegatedKey,
				Constraints:  map[string]any{},
				DelegationID: delegationID,
				IssuedAt:     issuedAt,
				ExpiresAt:    expiresAt,
			})
			if err != nil {
				http.Error(w, "tbs", http.StatusInternalServerError)
				return
			}
			rVal, sVal, err := ecdsa.Sign(rand.Reader, state.privateKey, tbs.SigStructureDigest)
			if err != nil {
				http.Error(w, "sign", http.StatusInternalServerError)
				return
			}
			sig := make([]byte, 64)
			rVal.FillBytes(sig[0:32])
			sVal.FillBytes(sig[32:64])
			certBytes, err := delegationcert.AssembleDelegationCert(tbs, sig)
			if err != nil {
				http.Error(w, "assemble", http.StatusInternalServerError)
				return
			}
			resp := delegationcert.DelegationIssueResponse{
				Version:     1,
				IssuedAt:    int64(issuedAt),
				ExpiresAt:   int64(expiresAt),
				Certificate: certBytes,
			}
			respBytes, _ := cbor.Marshal(resp)
			w.Header().Set("Content-Type", "application/cbor")
			_, _ = w.Write(respBytes)
			return
		}

		// Match POST /api/keys/<logIdHex>/sign - sign digest using CBOR
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sign") {
			body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}

			var req sealer.CustodianSignRequest
			if err := cbor.Unmarshal(body, &req); err != nil {
				http.Error(w, "cbor unmarshal", http.StatusBadRequest)
				return
			}

			// Sign the digest with the custody key
			var rVal, sVal *big.Int
			rVal, sVal, err = ecdsa.Sign(rand.Reader, state.privateKey, req.PayloadHash)
			if err != nil {
				http.Error(w, "sign", http.StatusInternalServerError)
				return
			}

			// Return r||s concatenated signature (fixed 64 bytes for P-256)
			sig := make([]byte, 64)
			rVal.FillBytes(sig[0:32])
			sVal.FillBytes(sig[32:64])

			resp := sealer.CustodianSignResponse{
				Signature: sig,
			}
			respBytes, _ := cbor.Marshal(resp)
			w.Header().Set("Content-Type", "application/cbor")
			_, _ = w.Write(respBytes)
			return
		}

		http.NotFound(w, r)
	}))
}

func fakeLogIDHexFromWire(logID []byte) (string, error) {
	if len(logID) == 16 {
		return hex.EncodeToString(logID), nil
	}
	if len(logID) == 32 {
		return strings.ToLower(string(logID)), nil
	}
	return "", fmt.Errorf("invalid log id length")
}

func fakeKidFromECDSAPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("nil public key")
	}
	uncompressed := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	sum := sha256.Sum256(uncompressed)
	kid := make([]byte, 16)
	copy(kid, sum[:16])
	return kid, nil
}
