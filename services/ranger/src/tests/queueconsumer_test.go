//go:build integration
// +build integration

package tests

import (
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/forestrie/arbor/services/ranger"
	"github.com/forestrie/arbor/services/ranger/committer"
	"github.com/forestrie/arbor/services/ranger/consumer"
	"github.com/forestrie/go-merklelog-provider-testing/mmrtesting"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
)

func Test_QueueConsumer_singleMessage(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_firstMassif"))
	g := tc.GetG()

	logID := g.NewLogID()

	// Build a logger and shared HTTP client for the consumer/committer stack
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	httpClient := ranger.NewHTTPClient(log)

	// Derive an R2 write URL from the MinIO-backed test configuration
	endpoint := strings.TrimRight(tc.cfg.Endpoint, "/")
	bucket := strings.Trim(tc.cfg.Bucket, "/")
	r2WriteURL, err := url.JoinPath(endpoint, bucket)
	require.NoError(t, err)

	// Committer writes leaves into the MinIO-backed merklelog store
	comm, err := committer.NewCommitter(ranger.Config{
		R2WriteURL:         r2WriteURL,
		R2WriterToken:      tc.cfg.BearerToken,
		AWSAccessKeyID:     tc.cfg.AccessKeyID,
		AWSSecretAccessKey: tc.cfg.SecretAccessKey,
		AWSRegion:          tc.cfg.Region,
		MassifHeight:       14,
		CommitmentEpoch:    1,
		TrustCanopy:        false,
		WorkerCIDR:         "0.0.0.0/16",
		PodIP:              "10.0.0.1",
	}, httpClient, log)
	require.NoError(t, err)

	qconsumer := consumer.NewQueueConsumer(
		ranger.Config{
			TrustCanopy:         true,
			MassifHeight:        14,
			CommitmentEpoch:     1,
			SuppressAcknowledge: true,
		},
		httpClient, log, comm)

	m1 := makeQueueMessage1(tc, logID, 0, []byte("hello ranger"))
	qbatch := consumer.QueuePullResult{
		Messages: []consumer.QueueMessage{
			m1,
		},
	}
	err = qconsumer.ProcessBatchWithCommitter(t.Context(), &qbatch)
	require.NoError(t, err)
}

func Test_QueueConsumer_multiLogBatches(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_multiLogBatches"))
	g := tc.GetG()

	// Build a logger and shared HTTP client for the consumer/committer stack.
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	httpClient := ranger.NewHTTPClient(log)

	// Derive an R2 write URL from the MinIO-backed test configuration.
	endpoint := strings.TrimRight(tc.cfg.Endpoint, "/")
	bucket := strings.Trim(tc.cfg.Bucket, "/")
	r2WriteURL, err := url.JoinPath(endpoint, bucket)
	require.NoError(t, err)

	massifHeight := uint8(14)

	// Committer writes leaves into the MinIO-backed merklelog store.
	comm, err := committer.NewCommitter(ranger.Config{
		R2WriteURL:         r2WriteURL,
		R2WriterToken:      tc.cfg.BearerToken,
		AWSAccessKeyID:     tc.cfg.AccessKeyID,
		AWSSecretAccessKey: tc.cfg.SecretAccessKey,
		AWSRegion:          tc.cfg.Region,
		MassifHeight:       massifHeight,
		CommitmentEpoch:    1,
		TrustCanopy:        false,
		WorkerCIDR:         "0.0.0.0/16",
		PodIP:              "10.0.0.1",
	}, httpClient, log)
	require.NoError(t, err)

	qconsumer := consumer.NewQueueConsumer(
		ranger.Config{
			TrustCanopy:         true,
			MassifHeight:        massifHeight,
			CommitmentEpoch:     1,
			SuppressAcknowledge: true,
		},
		httpClient, log, comm)

	type logInfo struct {
		id     massifstorage.LogID
		leaves int
	}

	tests := []struct {
		name  string
		build func(t *testing.T) ([]logInfo, [][]consumer.QueueMessage)
	}{
		{
			name: "singleLog_presorted_twoBatches",
			build: func(t *testing.T) ([]logInfo, [][]consumer.QueueMessage) {
				logA := g.NewLogID()
				tc.DeleteLog(logA)
				msgsA := makeMessagesForLog(tc, logA, 20)
				batches := [][]consumer.QueueMessage{
					msgsA[:10],
					msgsA[10:],
				}
				return []logInfo{{id: logA, leaves: len(msgsA)}}, batches
			},
		},
		{
			name: "twoLogs_shuffled_singleBatch",
			build: func(t *testing.T) ([]logInfo, [][]consumer.QueueMessage) {
				logA := g.NewLogID()
				tc.DeleteLog(logA)
				logB := g.NewLogID()
				tc.DeleteLog(logB)
				msgsA := makeMessagesForLog(tc, logA, 20)
				msgsB := makeMessagesForLog(tc, logB, 50)

				batch := shuffleMessages(tc, combineMessageSlices(t, msgsA, msgsB))

				return []logInfo{
					{id: logA, leaves: len(msgsA)},
					{id: logB, leaves: len(msgsB)},
				}, [][]consumer.QueueMessage{batch}
			},
		},
		{
			name: "threeLogs_mixedPresortedAndShuffled",
			build: func(t *testing.T) ([]logInfo, [][]consumer.QueueMessage) {
				logA := g.NewLogID()
				logB := g.NewLogID()
				logC := g.NewLogID()

				tc.DeleteLog(logA)
				tc.DeleteLog(logB)
				tc.DeleteLog(logC)

				msgsA := makeMessagesForLog(tc, logA, 20)
				msgsB := makeMessagesForLog(tc, logB, 50)
				msgsC := makeMessagesForLog(tc, logC, 80)

				batches := [][]consumer.QueueMessage{
					// First batch: presorted messages from logB only.
					msgsB[:25],
					// Second batch: mixed messages from all logs, shuffled.
					shuffleMessages(tc, combineMessageSlices(t,
						msgsA[10:],
						msgsB[25:],
						msgsC[:40],
					)),
					// Third batch: remaining messages for logC in presorted order.
					msgsC[40:],
				}

				return []logInfo{
					{id: logA, leaves: len(msgsA)},
					{id: logB, leaves: len(msgsB)},
					{id: logC, leaves: len(msgsC)},
				}, batches
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			logs, batches := tt.build(t)

			for batchIdx, msgs := range batches {
				qbatch := consumer.QueuePullResult{Messages: msgs}

				// Even with multiple logs present in the same batches and
				// shuffled ordering, the consumer/committer stack should
				// process all messages without error.
				err := qconsumer.ProcessBatchWithCommitter(t.Context(), &qbatch)
				require.NoErrorf(t, err, "batch %d in test %s", batchIdx, tt.name)
				assertNoMessageErrors(t, &qbatch)
			}

			// After processing all batches, verify massif counts per log.
			for _, li := range logs {
				if li.leaves == 0 {
					continue
				}
				// MassifFromLeaf gives the massif index (0-based) for the last leaf;
				// add 1 to obtain the expected massif count for this log.
				lastLeafIndex := uint64(li.leaves - 1)
				expectedMassifs := uint32(massifs.MassifFromLeaf(massifHeight, lastLeafIndex) + 1)
				assertMassifCount(t, r2WriteURL, tc.cfg.BearerToken, tc.cfg.AccessKeyID, tc.cfg.SecretAccessKey, tc.cfg.Region, massifHeight, httpClient, log, li.id, expectedMassifs)
			}
		})
	}
}

func Test_QueueConsumer_batchSizes(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_batchSizes"))
	g := tc.GetG()

	logID := g.NewLogID()
	tc.DeleteLog(logID)

	// Build a logger and shared HTTP client for the consumer/committer stack
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	httpClient := ranger.NewHTTPClient(log)

	// Derive an R2 write URL from the MinIO-backed test configuration
	endpoint := strings.TrimRight(tc.cfg.Endpoint, "/")
	bucket := strings.Trim(tc.cfg.Bucket, "/")
	r2WriteURL, err := url.JoinPath(endpoint, bucket)
	require.NoError(t, err)

	// Committer writes leaves into the MinIO-backed merklelog store
	comm, err := committer.NewCommitter(ranger.Config{
		R2WriteURL:         r2WriteURL,
		R2WriterToken:      tc.cfg.BearerToken,
		AWSAccessKeyID:     tc.cfg.AccessKeyID,
		AWSSecretAccessKey: tc.cfg.SecretAccessKey,
		AWSRegion:          tc.cfg.Region,
		MassifHeight:       14,
		CommitmentEpoch:    1,
		TrustCanopy:        false,
		WorkerCIDR:         "0.0.0.0/16",
		PodIP:              "10.0.0.1",
	}, httpClient, log)
	require.NoError(t, err)

	qconsumer := consumer.NewQueueConsumer(
		ranger.Config{
			TrustCanopy:         true,
			MassifHeight:        14,
			CommitmentEpoch:     1,
			SuppressAcknowledge: true,
		},
		httpClient, log, comm)

	tests := []struct {
		name         string
		messageCount int
	}{
		{"single", 1},
		{"small", 3},
		{"medium", 43},
		{"larger", 105},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messages := make([]consumer.QueueMessage, 0, tt.messageCount)
			for i := 0; i < tt.messageCount; i++ {
				messages = append(messages, makeQueueMessage1(tc, logID, uint64(i), []byte("hello ranger")))
			}

			qbatch := consumer.QueuePullResult{
				Messages: messages,
			}

			// ProcessBatchWithCommitter works with the provided qbatch; this
			// table-driven test ensures a variety of batch sizes for a single
			// log do not produce errors.
			err := qconsumer.ProcessBatchWithCommitter(t.Context(), &qbatch)
			require.NoError(t, err)
		})
	}
}

func Test_QueueConsumer_multiLogBatches_massifBoundaries(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_multiLogBatches_massifBoundaries"))
	g := tc.GetG()

	// Build a logger and shared HTTP client for the consumer/committer stack.
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	httpClient := ranger.NewHTTPClient(log)

	// Derive an R2 write URL from the MinIO-backed test configuration.
	endpoint := strings.TrimRight(tc.cfg.Endpoint, "/")
	bucket := strings.Trim(tc.cfg.Bucket, "/")
	r2WriteURL, err := url.JoinPath(endpoint, bucket)
	require.NoError(t, err)

	massifHeight := uint8(4)

	// Compute leaves-per-massif for this height so we can design batches that
	// deliberately cross massif boundaries for each log.
	leavesPerMassif := int(mmr.HeightIndexLeafCount(uint64(massifHeight - 1)))
	if leavesPerMassif <= 0 {
		t.Fatalf("leavesPerMassif must be positive, got %d", leavesPerMassif)
	}

	// Committer writes leaves into the MinIO-backed merklelog store.
	comm, err := committer.NewCommitter(ranger.Config{
		R2WriteURL:         r2WriteURL,
		R2WriterToken:      tc.cfg.BearerToken,
		AWSAccessKeyID:     tc.cfg.AccessKeyID,
		AWSSecretAccessKey: tc.cfg.SecretAccessKey,
		AWSRegion:          tc.cfg.Region,
		MassifHeight:       massifHeight,
		CommitmentEpoch:    1,
		TrustCanopy:        false,
		WorkerCIDR:         "0.0.0.0/16",
		PodIP:              "10.0.0.1",
	}, httpClient, log)
	require.NoError(t, err)

	qconsumer := consumer.NewQueueConsumer(
		ranger.Config{
			TrustCanopy:         true,
			MassifHeight:        massifHeight,
			CommitmentEpoch:     1,
			SuppressAcknowledge: true,
		},
		httpClient, log, comm)

	type logInfo struct {
		id     massifstorage.LogID
		leaves int
	}

	tests := []struct {
		name  string
		build func(t *testing.T) ([]logInfo, [][]consumer.QueueMessage)
	}{
		{
			name: "twoLogs_crossSingleBoundary",
			build: func(t *testing.T) ([]logInfo, [][]consumer.QueueMessage) {
				// Each log has more than one massif worth of leaves so that the
				// first massif boundary is crossed while processing mixed batches.
				logA := g.NewLogID()
				logB := g.NewLogID()

				tc.DeleteLog(logA)
				tc.DeleteLog(logB)

				countA := leavesPerMassif + leavesPerMassif/2 // crosses once
				countB := leavesPerMassif + 2                 // crosses once

				msgsA := makeMessagesForLog(tc, logA, countA)
				msgsB := makeMessagesForLog(tc, logB, countB)

				// Batch 0: both logs receive leavesPerMassif-1 messages, staying
				// just before the massif boundary.
				batch0 := shuffleMessages(tc, combineMessageSlices(t,
					msgsA[:leavesPerMassif-1],
					msgsB[:leavesPerMassif-1],
				))

				// Batch 1: the remaining messages for both logs, causing each to
				// cross at least one massif boundary.
				batch1 := shuffleMessages(tc, combineMessageSlices(t,
					msgsA[leavesPerMassif-1:],
					msgsB[leavesPerMassif-1:],
				))

				logs := []logInfo{
					{id: logA, leaves: countA},
					{id: logB, leaves: countB},
				}

				return logs, [][]consumer.QueueMessage{batch0, batch1}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			logs, batches := tt.build(t)

			for batchIdx, msgs := range batches {
				qbatch := consumer.QueuePullResult{Messages: msgs}

				// Process the mixed batches; each per-log massif append should
				// cope with boundaries even when batches are interleaved.
				err := qconsumer.ProcessBatchWithCommitter(t.Context(), &qbatch)
				require.NoErrorf(t, err, "batch %d in test %s", batchIdx, tt.name)
				assertNoMessageErrors(t, &qbatch)
			}

			// After all batches, verify massif counts per log using the
			// canonical MassifFromLeaf helper.
			for _, li := range logs {
				if li.leaves == 0 {
					continue
				}
				lastLeafIndex := uint64(li.leaves - 1)
				expectedMassifs := uint32(massifs.MassifFromLeaf(massifHeight, lastLeafIndex) + 1)
				assertMassifCount(t, r2WriteURL, tc.cfg.BearerToken, tc.cfg.AccessKeyID, tc.cfg.SecretAccessKey, tc.cfg.Region, massifHeight, httpClient, log, li.id, expectedMassifs)
			}
		})
	}
}

func Test_QueueConsumer_massifBoundaries(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_massifBoundaries"))
	g := tc.GetG()

	// For massifHeight=3, each massif holds 7 mmr nodes. Convert that into a
	// leaf count using the mmr.LeafCount helper so we can reason in terms of
	// leaves for this queue-consumer test.
	nodesPerMassif := uint64(7)
	leavesPerMassif := int(mmr.LeafCount(nodesPerMassif))
	if leavesPerMassif <= 0 {
		t.Fatalf("leavesPerMassif must be positive, got %d", leavesPerMassif)
	}

	// Derive batch patterns in terms of leaves rather than assuming
	// "7 leaves per massif" directly.
	partialFirst := leavesPerMassif / 2
	if partialFirst == 0 {
		partialFirst = 1
	}
	completeFirstAndStartSecond := leavesPerMassif + (leavesPerMassif - partialFirst)

	tests := []struct {
		name    string
		batches []int
	}{
		{
			name:    "threeMassifsThenPartialSecondBatch",
			batches: []int{3 * leavesPerMassif, leavesPerMassif / 2},
		},
		{
			name:    "threeMassifsThreeBatchesExact",
			batches: []int{leavesPerMassif, leavesPerMassif, leavesPerMassif},
		},
		{
			name:    "partialFirstThenCompleteAndStartNext",
			batches: []int{partialFirst, completeFirstAndStartSecond},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			logID := g.NewLogID()
			tc.DeleteLog(logID)

			// Build a logger and shared HTTP client for the consumer/committer stack
			log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
			httpClient := ranger.NewHTTPClient(log)

			// Derive an R2 write URL from the MinIO-backed test configuration
			endpoint := strings.TrimRight(tc.cfg.Endpoint, "/")
			bucket := strings.Trim(tc.cfg.Bucket, "/")
			r2WriteURL, err := url.JoinPath(endpoint, bucket)
			require.NoError(t, err)

			// Committer writes leaves into the MinIO-backed merklelog store
			comm, err := committer.NewCommitter(ranger.Config{
				R2WriteURL:         r2WriteURL,
				R2WriterToken:      tc.cfg.BearerToken,
				AWSAccessKeyID:     tc.cfg.AccessKeyID,
				AWSSecretAccessKey: tc.cfg.SecretAccessKey,
				AWSRegion:          tc.cfg.Region,
				MassifHeight:       3,
				CommitmentEpoch:    1,
				TrustCanopy:        false,
				WorkerCIDR:         "0.0.0.0/16",
				PodIP:              "10.0.0.1",
			}, httpClient, log)
			require.NoError(t, err)

			qconsumer := consumer.NewQueueConsumer(
				ranger.Config{
					TrustCanopy:         true,
					MassifHeight:        3,
					CommitmentEpoch:     1,
					SuppressAcknowledge: true,
				},
				httpClient, log, comm)

			var fenceIndex uint64
			for batchIdx, count := range tt.batches {
				messages := make([]consumer.QueueMessage, 0, count)
				for i := 0; i < count; i++ {
					messages = append(messages, makeQueueMessage1(tc, logID, fenceIndex, []byte("hello ranger")))
					fenceIndex++
				}

				qbatch := consumer.QueuePullResult{Messages: messages}

				// Each batch should be processed without error, even when it
				// crosses massif boundaries in the underlying merklelog.
				err = qconsumer.ProcessBatchWithCommitter(t.Context(), &qbatch)
				require.NoErrorf(t, err, "batch %d in test %s", batchIdx, tt.name)
				assertNoMessageErrors(t, &qbatch)
			}

			totalLeaves := 0
			for _, count := range tt.batches {
				totalLeaves += count
			}

			// massifHeight=3 => capacity 7 mmr nodes per massif. We derived the
			// corresponding leaf count for those nodes above as leavesPerMassif.
			expectedMassifs := uint32((totalLeaves + leavesPerMassif - 1) / leavesPerMassif)
			assertMassifCount(t, r2WriteURL, tc.cfg.BearerToken, tc.cfg.AccessKeyID, tc.cfg.SecretAccessKey, tc.cfg.Region, 3, httpClient, log, logID, expectedMassifs)
		})
	}
}

// combineMessageSlices flattens a set of message slices into a single slice.
func combineMessageSlices(t *testing.T, batches ...[]consumer.QueueMessage) []consumer.QueueMessage {
	t.Helper()

	total := 0
	for _, batch := range batches {
		total += len(batch)
	}

	combined := make([]consumer.QueueMessage, 0, total)
	for _, batch := range batches {
		combined = append(combined, batch...)
	}

	return combined
}

// shuffleMessages permutes the provided messages slice using the test
// context's generator for entropy.
func shuffleMessages(tc *TestContext, messages []consumer.QueueMessage) []consumer.QueueMessage {
	g := tc.GetG()

	// Fisher-Yates shuffle in-place.
	for i := len(messages) - 1; i > 0; i-- {
		j := g.Intn(i + 1)
		messages[i], messages[j] = messages[j], messages[i]
	}

	return messages
}

// makeMessagesForLog builds a slice of QueueMessage instances for a single
// logID, using random 4-word content for each message.
func makeMessagesForLog(tc *TestContext, logID massifstorage.LogID, count int) []consumer.QueueMessage {
	g := tc.GetG()

	messages := make([]consumer.QueueMessage, 0, count)
	for i := 0; i < count; i++ {
		content := []byte(g.MultiWordString(4))
		messages = append(messages, makeQueueMessage1(tc, logID, uint64(i), content))
	}

	return messages
}
