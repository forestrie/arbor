package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	sealer "github.com/forestrie/arbor/services/sealer"
	"github.com/forestrie/arbor/services/sealer/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// ackRecordingConsumer is a QueueConsumer whose queue records the lease ids
// it is asked to ack.
func ackRecordingConsumer(t *testing.T) (*QueueConsumer, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var acked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Acks []struct {
				LeaseID string `json:"lease_id"`
			} `json:"acks"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		for _, a := range body.Acks {
			acked = append(acked, a.LeaseID)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"result":{"ackCount":1,"retryCount":0},"errors":[]}`)
	}))
	t.Cleanup(srv.Close)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	q := &QueueConsumer{
		cfg:        sealer.Config{QueueURL: srv.URL + "/messages", QueueToken: "t"},
		httpClient: sealer.NewHTTPClient(logger),
		logger:     logger,
		metrics:    metrics.NewMetrics(prometheus.NewRegistry()),
	}
	return q, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := slices.Clone(acked)
		slices.Sort(out)
		return out
	}
}

// A failed seal settles the log's queued work by its cause: a conflicted
// log's messages are acked, since it is never sealed again; a pending
// authority or delegation leaves them for redelivery; anything else is a
// failure, also redelivered.
func TestSettleFailedSealByCause(t *testing.T) {
	work := &logWork{messages: []QueueMessage{{ID: "a", LeaseID: "lease-a"}, {ID: "b", LeaseID: "lease-b"}}}
	cases := []struct {
		err    error
		acked  []string
		failed bool
	}{
		{fmt.Errorf("resolve authority: %w", sealer.ErrLogConflicted), []string{"lease-a", "lease-b"}, false},
		{fmt.Errorf("resolve authority: %w", sealer.ErrAuthorityPending), nil, false},
		{fmt.Errorf("issuer: %w", sealer.ErrDelegationPending), nil, false},
		{errors.New("r2 read failed"), nil, true},
	}
	for _, tc := range cases {
		q, acked := ackRecordingConsumer(t)
		failed := q.settleFailedSeal(context.Background(), work, tc.err)
		if got := acked(); !slices.Equal(got, tc.acked) || failed != tc.failed {
			t.Errorf("%v: acked %v failed=%v, want acked %v failed=%v", tc.err, got, failed, tc.acked, tc.failed)
		}
	}
}
