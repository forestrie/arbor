package ingress

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/forestrie/arbor/services/ranger"
)

// ackServer answers every ack with {acked: acked} and sends each decoded
// request on got.
func ackServer(t *testing.T, acked int, got chan<- AckRequest) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req AckRequest
		if err := cbor.Unmarshal(body, &req); err != nil {
			t.Errorf("decode ack request: %v", err)
		}
		got <- req
		resp, err := canonicalCBOR.Marshal(AckResponse{Acked: acked})
		if err != nil {
			t.Errorf("encode ack response: %v", err)
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAckNamesThePulledBatch: the ack echoes the LogGroup's seq range and
// the pull's lease, which the DO matches against the rows it leased
// (FOR-655), and a full ack publishes the seal hints.
func TestAckNamesThePulledBatch(t *testing.T) {
	got := make(chan AckRequest, 1)
	srv := ackServer(t, 1, got)
	pub := &countingPublisher{calls: make(chan []string, 1)}
	c := &Consumer{
		cfg:        ranger.Config{MassifHeight: 14},
		httpClient: ranger.NewHTTPClient(ingressTestLogger()),
		logger:     ingressTestLogger(),
		committer:  &stubCommitter{result: &CommitResult{Committed: 1, FirstLeafIndex: 7, MassifObjectKeys: []string{"k"}}},
		sealHints:  pub,
		ackURL:     srv.URL,
	}
	group := testGroup()
	group.SeqLo, group.SeqHi = 3, 9

	c.processLogGroup(context.Background(), group, testLeaseExpiry)

	req := <-got
	if req.SeqLo != 3 || req.SeqHi != 9 || req.LeaseExpiry != testLeaseExpiry {
		t.Errorf("ack seq %d..%d lease %d, want 3..9 lease %d",
			req.SeqLo, req.SeqHi, req.LeaseExpiry, testLeaseExpiry)
	}
	if req.Limit != 1 || req.FirstLeafIndex != 7 {
		t.Errorf("ack limit %d first %d, want 1 and 7", req.Limit, req.FirstLeafIndex)
	}
	select {
	case <-pub.calls:
	case <-time.After(2 * time.Second):
		t.Fatal("no seal hint after a full ack")
	}
}

// TestShortAckIsAFailedAck: a 200 that applied fewer entries than the batch
// is not an ack of the batch, so no seal hint is published; the batch
// redelivers.
func TestShortAckIsAFailedAck(t *testing.T) {
	got := make(chan AckRequest, 1)
	srv := ackServer(t, 0, got)
	pub := &countingPublisher{calls: make(chan []string, 1)}
	c := &Consumer{
		cfg:        ranger.Config{MassifHeight: 14},
		httpClient: ranger.NewHTTPClient(ingressTestLogger()),
		logger:     ingressTestLogger(),
		committer:  &stubCommitter{result: &CommitResult{Committed: 1, MassifObjectKeys: []string{"k"}}},
		sealHints:  pub,
		ackURL:     srv.URL,
	}

	c.processLogGroup(context.Background(), testGroup(), testLeaseExpiry)
	<-got

	select {
	case keys := <-pub.calls:
		t.Fatalf("seal hint published after a short ack: %v", keys)
	case <-time.After(300 * time.Millisecond):
	}
}
