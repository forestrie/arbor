package sealhint

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/forestrie/arbor/services/ranger"
	"github.com/forestrie/arbor/services/ranger/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestPublisher(t *testing.T, queueURL string) (*Publisher, *metrics.Metrics) {
	t.Helper()
	m := metrics.NewMetrics(prometheus.NewRegistry())
	p := New(ranger.Config{
		SealHintQueueURL:   queueURL,
		SealHintQueueToken: "test-token",
	}, ranger.NewHTTPClient(testLogger()), testLogger(), m)
	if queueURL != "" && p == nil {
		t.Fatal("expected enabled publisher")
	}
	return p, m
}

// sealerNotification mirrors the sealer consumer's R2Notification decode so the
// test asserts the exact wire contract: the queue push body is a JSON string
// token containing the notification JSON (the sealer double-decodes), the
// action gate passes, and the hint source is attributable.
type sealerNotification struct {
	Action     string               `json:"action"`
	Object     struct{ Key string } `json:"object"`
	HintSource string               `json:"hintSource"`
}

func TestPublishSealHintsBodyMatchesSealerContract(t *testing.T) {
	var gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/messages" {
			t.Errorf("push path = %q, want /messages", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, m := newTestPublisher(t, srv.URL)
	p.PublishSealHints(context.Background(), []string{"v2/merklelog/massifs/14/3062ea57-c184-41d8-bd61-296b02c680d8/0000000000000000.log"})

	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}

	// Decode the push request, then replay the sealer's double-decode.
	var push struct {
		Body        string `json:"body"`
		ContentType string `json:"content_type"`
	}
	if err := json.Unmarshal(gotBody, &push); err != nil {
		t.Fatalf("push request decode: %v", err)
	}
	if push.ContentType != "text" {
		t.Errorf("content_type = %q, want text (pull must deliver a JSON string token)", push.ContentType)
	}
	var note sealerNotification
	if err := json.Unmarshal([]byte(push.Body), &note); err != nil {
		t.Fatalf("notification decode (sealer inner decode): %v", err)
	}
	if note.Action != "PutObject" {
		t.Errorf("action = %q, want PutObject (sealer consumer gates on it)", note.Action)
	}
	if note.Object.Key != "v2/merklelog/massifs/14/3062ea57-c184-41d8-bd61-296b02c680d8/0000000000000000.log" {
		t.Errorf("object key = %q", note.Object.Key)
	}
	if note.HintSource != Source {
		t.Errorf("hintSource = %q, want %q", note.HintSource, Source)
	}

	if got := testutil.ToFloat64(m.SealHintsPublishedTotal); got != 1 {
		t.Errorf("published counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.SealHintPublishFailuresTotal); got != 0 {
		t.Errorf("failure counter = %v, want 0", got)
	}
}

func TestPublishSealHintsRetriesThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, m := newTestPublisher(t, srv.URL)
	p.PublishSealHints(context.Background(), []string{"k"})

	if calls.Load() != 2 {
		t.Errorf("attempts = %d, want 2", calls.Load())
	}
	if got := testutil.ToFloat64(m.SealHintsPublishedTotal); got != 1 {
		t.Errorf("published counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.SealHintPublishFailuresTotal); got != 0 {
		t.Errorf("failure counter = %v, want 0", got)
	}
}

func TestPublishSealHintsFailureIsCountedNotRaised(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p, m := newTestPublisher(t, srv.URL)
	// Must not panic or surface an error — fire-and-forget.
	p.PublishSealHints(context.Background(), []string{"k1", "k2"})

	if calls.Load() != 4 {
		t.Errorf("attempts = %d, want 4 (2 keys x 2 bounded attempts)", calls.Load())
	}
	if got := testutil.ToFloat64(m.SealHintPublishFailuresTotal); got != 2 {
		t.Errorf("failure counter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.SealHintsPublishedTotal); got != 0 {
		t.Errorf("published counter = %v, want 0", got)
	}
}

func TestDisabledPublisherIsNilAndSafe(t *testing.T) {
	p, _ := newTestPublisher(t, "")
	if p != nil {
		t.Fatal("expected nil publisher when SEAL_HINT_QUEUE_URL is empty")
	}
	// A nil *Publisher must be safe to call (fire-and-forget contract).
	p.PublishSealHints(context.Background(), []string{"k"})
}

func TestNewNormalizesQueueURL(t *testing.T) {
	m := metrics.NewMetrics(prometheus.NewRegistry())
	for _, raw := range []string{
		"https://api.example/accounts/a/queues/q",
		"https://api.example/accounts/a/queues/q/",
		"https://api.example/accounts/a/queues/q/messages",
	} {
		p := New(ranger.Config{SealHintQueueURL: raw}, ranger.NewHTTPClient(testLogger()), testLogger(), m)
		if p == nil {
			t.Fatalf("publisher nil for %q", raw)
		}
		if p.pushURL != "https://api.example/accounts/a/queues/q/messages" {
			t.Errorf("pushURL for %q = %q", raw, p.pushURL)
		}
	}
}
