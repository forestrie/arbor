package publisher

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// fakeUnivocity answers univocity's GET /api/logs/{logId}/authority with a
// settable state, and counts the requests.
type fakeUnivocity struct {
	*httptest.Server
	mu     sync.Mutex
	status int
	state  string
	final  bool
	calls  int
}

func newFakeUnivocity(t *testing.T, state string, final bool) *fakeUnivocity {
	t.Helper()
	f := &fakeUnivocity{state: state, final: final}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/logs/") ||
			!strings.HasSuffix(r.URL.Path, "/authority") {
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		f.calls++
		status, state, final := f.status, f.state, f.final
		f.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		body, _ := cbor.Marshal(struct {
			State string `cbor:"state"`
			Final bool   `cbor:"final"`
		}{state, final})
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(body)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeUnivocity) set(status int, state string, final bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.state, f.final = status, state, final
}

func (f *fakeUnivocity) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// countingGrants is a grant store with nothing in it, which counts reads: a
// read means Assemble went past the authority check.
type countingGrants struct {
	mu    sync.Mutex
	reads int
}

func (g *countingGrants) Get(context.Context, string) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reads++
	return nil, errors.New("grant store unavailable")
}

func (g *countingGrants) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.reads
}

func authorityPublisher(f *fakeUnivocity) (*Publisher, *countingGrants) {
	grants := &countingGrants{}
	return &Publisher{
		grants:    grants,
		authority: NewUnivocityAuthority(f.URL, f.Client()),
		logger:    testLogger(),
	}, grants
}

const conflictedLog = "3a3b3c3d-3e3f-4041-8243-444546474849"

// A log univocity reports conflicted is final: its checkpoint is settled
// without reading anything else, and univocity is not asked again.
func TestAssembleConflictedLogIsFinal(t *testing.T) {
	univ := newFakeUnivocity(t, "conflicted", true)
	p, grants := authorityPublisher(univ)
	key := ckpt(conflictedLog, 2)

	for i := range 3 {
		if i == 1 {
			// Univocity never changes a conflicted answer; the publisher
			// must not depend on asking it again.
			univ.set(0, "anchored", true)
		}
		calldata, res, ready, err := p.Assemble(context.Background(), key)
		if err != nil || ready || calldata != nil {
			t.Fatalf("assemble %d: ready=%v err=%v, want a settled result", i, ready, err)
		}
		if res.Status != StatusConflicted || !res.ShouldAck() {
			t.Fatalf("assemble %d: status=%v ack=%v, want conflicted and acked", i, res.Status, res.ShouldAck())
		}
	}
	if n := univ.requests(); n != 1 {
		t.Fatalf("univocity asked %d times, want 1", n)
	}
	if n := grants.count(); n != 0 {
		t.Fatalf("grant store read %d times for a conflicted log, want 0", n)
	}
}

// A log univocity does not report conflicted is published as usual, whatever
// its state: a pending log's first checkpoint is what anchors it. Univocity
// is asked again for each publish until its answer is final.
func TestAssembleAsksUnivocityUntilFinal(t *testing.T) {
	univ := newFakeUnivocity(t, "sequenced", false)
	p, grants := authorityPublisher(univ)
	key := ckpt(conflictedLog, 0)

	assemble := func(step string, wantAsked int) {
		t.Helper()
		before := grants.count()
		_, res, _, _ := p.Assemble(context.Background(), key)
		if res.Status == StatusConflicted {
			t.Fatalf("%s: settled as conflicted", step)
		}
		if grants.count() == before {
			t.Fatalf("%s: publish stopped at the authority check", step)
		}
		if n := univ.requests(); n != wantAsked {
			t.Fatalf("%s: univocity asked %d times, want %d", step, n, wantAsked)
		}
	}
	assemble("sequenced", 1)
	assemble("sequenced again", 2)
	univ.set(0, "anchored", true)
	assemble("anchored", 3)
	assemble("anchored again", 3)
}

// Without an answer from univocity the publish is retried, not made
// unchecked.
func TestAssembleRetriesWithoutUnivocityAnswer(t *testing.T) {
	univ := newFakeUnivocity(t, "", false)
	p, grants := authorityPublisher(univ)
	for _, status := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		univ.set(status, "", false)
		// Callers leave a message unacked on any error.
		_, _, ready, err := p.Assemble(context.Background(), ckpt(conflictedLog, 0))
		if err == nil || ready {
			t.Fatalf("status %d: ready=%v err=%v, want an error", status, ready, err)
		}
	}
	if n := grants.count(); n != 0 {
		t.Fatalf("grant store read %d times without univocity's answer, want 0", n)
	}
}
