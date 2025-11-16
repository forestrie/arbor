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
		R2WriteURL:      r2WriteURL,
		R2WriterToken:   tc.cfg.BearerToken,
		MassifHeight:    14,
		CommitmentEpoch: 1,
		TrustCanopy:     false,
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

func Test_QueueConsumer_batchSizes(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_batchSizes"))
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
		R2WriteURL:      r2WriteURL,
		R2WriterToken:   tc.cfg.BearerToken,
		MassifHeight:    14,
		CommitmentEpoch: 1,
		TrustCanopy:     false,
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
		name        string
		messageCount int
	}{
		{"single", 1},
		{"small", 2},
		{"medium", 4},
		{"larger", 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messages := make([]consumer.QueueMessage, 0, tt.messageCount)
			for i := 0; i < tt.messageCount; i++ {
				messages = append(messages, makeQueueMessage1(tc, logID, i, []byte("hello ranger")))
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
