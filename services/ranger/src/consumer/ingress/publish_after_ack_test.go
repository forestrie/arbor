package ingress

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/ranger"
)

type stubCommitter struct {
	result *CommitResult
	err    error
}

func (s *stubCommitter) CommitLogGroup(_ context.Context, _ []byte, _ []Entry) (*CommitResult, error) {
	return s.result, s.err
}

// blockingPublisher blocks in PublishSealHints until released, recording the
// keys it was called with. It stands in for a slow/dead hint queue.
type blockingPublisher struct {
	started chan struct{}
	release chan struct{}
	got     chan []string
}

func newBlockingPublisher() *blockingPublisher {
	return &blockingPublisher{
		started: make(chan struct{}),
		release: make(chan struct{}),
		got:     make(chan []string, 1),
	}
}

func (p *blockingPublisher) PublishSealHints(_ context.Context, keys []string) {
	close(p.started)
	<-p.release
	p.got <- keys
}

func ingressTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testGroup() LogGroup {
	return LogGroup{
		LogId:   []byte{0x30, 0x62, 0xea, 0x57, 0xc1, 0x84, 0x41, 0xd8, 0xbd, 0x61, 0x29, 0x6b, 0x02, 0xc6, 0x80, 0xd8},
		SeqLo:   1,
		Entries: []Entry{{ContentHash: make([]byte, 32)}},
	}
}

// TestProcessLogGroupDoesNotWaitOnHintPublish is the R1 acceptance
// (plan-2607-03): the seal-hint publish is detached, so a slow or dead hint
// queue must never stretch the shard's poll cadence — processLogGroup (which
// pollCycle's wg.Wait() gates the next pull on) returns while the publisher is
// still blocked, and the publisher still receives the committed massif keys.
func TestProcessLogGroupDoesNotWaitOnHintPublish(t *testing.T) {
	pub := newBlockingPublisher()
	keys := []string{"v2/merklelog/massifs/14/3062ea57-c184-41d8-bd61-296b02c680d8/0000000000000000.log"}
	c := &Consumer{
		cfg:       ranger.Config{SuppressAcknowledge: true, MassifHeight: 14},
		logger:    ingressTestLogger(),
		committer: &stubCommitter{result: &CommitResult{Committed: 1, MassifObjectKeys: keys}},
		sealHints: pub,
	}

	done := make(chan struct{})
	go func() {
		c.processLogGroup(context.Background(), testGroup())
		close(done)
	}()

	// The publish must have started (ordering: after commit + ack)…
	select {
	case <-pub.started:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher was never invoked")
	}
	// …and processLogGroup must return while the publisher is still blocked.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("processLogGroup blocked on the hint publish (R1 regression)")
	}

	close(pub.release)
	select {
	case got := <-pub.got:
		if len(got) != 1 || got[0] != keys[0] {
			t.Errorf("published keys = %v, want %v", got, keys)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publisher did not complete after release")
	}
}

// countingPublisher records invocations without blocking.
type countingPublisher struct{ calls chan []string }

func (p *countingPublisher) PublishSealHints(_ context.Context, keys []string) {
	p.calls <- keys
}

// TestProcessLogGroupNoHintOnAckFailure pins the ordering half of the ADR
// contract (and plan-2607-03 R8): hints publish only after a SUCCESSFUL ack.
// On ack failure the entries redeliver and the retry hints.
func TestProcessLogGroupNoHintOnAckFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	pub := &countingPublisher{calls: make(chan []string, 1)}
	c := &Consumer{
		cfg:        ranger.Config{MassifHeight: 14},
		httpClient: ranger.NewHTTPClient(ingressTestLogger()),
		logger:     ingressTestLogger(),
		committer:  &stubCommitter{result: &CommitResult{Committed: 1, MassifObjectKeys: []string{"k"}}},
		sealHints:  pub,
		ackURL:     srv.URL,
	}

	c.processLogGroup(context.Background(), testGroup())

	select {
	case got := <-pub.calls:
		t.Fatalf("publisher invoked despite ack failure: %v", got)
	case <-time.After(300 * time.Millisecond):
		// No publish — correct.
	}
}

// TestProcessLogGroupNoHintWhenNoKeys: a commit with no written massifs (or
// hints disabled via nil publisher) publishes nothing and does not panic.
func TestProcessLogGroupNoHintWhenNoKeys(t *testing.T) {
	pub := &countingPublisher{calls: make(chan []string, 1)}
	c := &Consumer{
		cfg:       ranger.Config{SuppressAcknowledge: true, MassifHeight: 14},
		logger:    ingressTestLogger(),
		committer: &stubCommitter{result: &CommitResult{Committed: 1}},
		sealHints: pub,
	}
	c.processLogGroup(context.Background(), testGroup())
	select {
	case got := <-pub.calls:
		t.Fatalf("publisher invoked with no keys: %v", got)
	case <-time.After(200 * time.Millisecond):
	}

	// nil publisher (feature off) must be safe on the same path.
	c.sealHints = nil
	c.committer = &stubCommitter{result: &CommitResult{Committed: 1, MassifObjectKeys: []string{"k"}}}
	c.processLogGroup(context.Background(), testGroup())
}
