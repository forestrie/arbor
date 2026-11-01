package sealer

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	"github.com/forestrie/arbor/services/sealer/metrics"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// countingLister stands in for R2 behind the resync's objectLister seam. It
// records every LIST and reports no objects, so a log that reaches the
// authoritative check stops at the height probe with a miss.
type countingLister struct {
	mu       sync.Mutex
	prefixes []string
}

func (l *countingLister) ListObjects(_ context.Context, prefix, _ string, _ int) (s3.ListResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prefixes = append(l.prefixes, prefix)
	return s3.ListResult{}, nil
}

func (l *countingLister) calls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prefixes)
}

// newTestResyncManager builds a manager whose R2 LISTs go to a
// countingLister. There is no s3Client, so a path that gets past an empty
// height probe (checkpoint reads) is out of reach of these tests.
func newTestResyncManager(cfg Config, httpClient *HTTPClient) (*ResyncManager, *countingLister) {
	lister := &countingLister{}
	return &ResyncManager{
		cfg:         cfg,
		httpClient:  httpClient,
		logger:      slog.Default(),
		lister:      lister,
		heightByLog: map[string]uint8{},
		heightMiss:  map[string]time.Time{},
		hintWarned:  map[string]bool{},
		sealedByLog: map[string]uint64{},
		factories:   nil,
	}, lister
}

// TestTickResetsCursorOnFetchError pins R1: a persistent 4xx from the active
// endpoint must not wedge the backstop — the cursor is reset so the next tick
// restarts the walk instead of re-sending a dead cursor.
func TestTickResetsCursorOnFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"title":"Invalid request"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	cfg := Config{
		CoordinatorRegisterURL: srv.URL,
		ResyncPageSize:         10,
		ResyncGraceSeconds:     3600,
		ResyncConcurrency:      1,
	}
	r, _ := newTestResyncManager(cfg, NewHTTPClient(slog.Default()))
	r.cursor = "eyJzIjozLCJrIjoiZmYifQ" // a stale opaque cursor

	r.tick(context.Background())

	if r.cursor != "" {
		t.Fatalf("cursor should reset to \"\" on fetch error, got %q", r.cursor)
	}
}

// TestHintFastPathSkipsWhenSealedCoversMmrEnd pins R4: when the cached sealed
// size already covers the furthest authorized index, checkAndReseal returns
// without any R2 access.
func TestHintFastPathSkipsWhenSealedCoversMmrEnd(t *testing.T) {
	r, lister := newTestResyncManager(Config{ResyncMassifHeights: []uint8{14}}, nil)
	const logID = "0123456789abcdef0123456789abcdef"
	r.sealedByLog[logID] = 100

	r.checkAndReseal(context.Background(), decodeActiveLog(t, `{"logIdHex32":"`+logID+`","mmrStart":"0","mmrEnd":"50"}`))
	if n := lister.calls(); n != 0 {
		t.Fatalf("fast path should skip R2, got %d LISTs", n)
	}

	// Control: a hint past the sealed size falls through to the height probe.
	r.checkAndReseal(context.Background(), decodeActiveLog(t, `{"logIdHex32":"`+logID+`","mmrStart":"0","mmrEnd":"101"}`))
	if n := lister.calls(); n == 0 {
		t.Fatal("an uncovered hint should reach the authoritative check")
	}
}

// TestHintFastPathAtMaxUint64 pins the fast path at the top of the uint64
// range: an mmrEnd of 2^64-1 arrives as a decimal string and compares exactly
// against the cached sealed size.
func TestHintFastPathAtMaxUint64(t *testing.T) {
	r, lister := newTestResyncManager(Config{ResyncMassifHeights: []uint8{14}}, nil)
	const logID = "0123456789abcdef0123456789abcdef"
	r.sealedByLog[logID] = math.MaxUint64

	r.checkAndReseal(context.Background(), decodeActiveLog(t,
		`{"logIdHex32":"`+logID+`","mmrStart":"18446744073709551614","mmrEnd":"18446744073709551615"}`))
	if n := lister.calls(); n != 0 {
		t.Fatalf("fast path should skip R2, got %d LISTs", n)
	}
}

// TestCheckAndResealMalformedHintRunsAuthoritativeCheck pins the handling
// of a malformed range value: it is treated as absent. The fast path is
// skipped (the cached sealed size would otherwise cover it), the
// authoritative head-vs-checkpoint check still runs, and each row bumps
// sealer_resync_malformed_hint_total. A JSON number is malformed too: it is
// never used as a value.
func TestCheckAndResealMalformedHintRunsAuthoritativeCheck(t *testing.T) {
	const logID = "0123456789abcdef0123456789abcdef"
	rows := []string{
		`{"logIdHex32":"` + logID + `","mmrStart":"0","mmrEnd":"042"}`,
		`{"logIdHex32":"` + logID + `","mmrStart":"0","mmrEnd":42}`,
		`{"logIdHex32":"` + logID + `","mmrStart":42,"mmrEnd":"50"}`,
		`{"logIdHex32":"` + logID + `","mmrStart":"0","mmrEnd":"18446744073709551616"}`,
	}
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			r, lister := newTestResyncManager(Config{ResyncMassifHeights: []uint8{14}, ResyncInterval: time.Second}, nil)
			r.metrics = metrics.NewMetrics(prometheus.NewRegistry())
			r.sealedByLog[logID] = math.MaxUint64 // covers any well-formed hint

			r.checkAndReseal(context.Background(), decodeActiveLog(t, row))

			if n := lister.calls(); n == 0 {
				t.Fatal("a malformed hint must not stop the authoritative check")
			}
			if got := testutil.ToFloat64(r.metrics.ResyncMalformedHintTotal); got != 1 {
				t.Fatalf("sealer_resync_malformed_hint_total = %v, want 1", got)
			}
		})
	}
}

// TestCheckAndResealMalformedHintWarnsOncePerLog pins the rate limit: the
// resync re-reads the active set every tick, so a persistently malformed row
// logs at WARN once per log (DEBUG after), while the counter keeps counting.
// A well-formed hint re-arms the WARN.
func TestCheckAndResealMalformedHintWarnsOncePerLog(t *testing.T) {
	var buf bytes.Buffer
	r, _ := newTestResyncManager(Config{ResyncMassifHeights: []uint8{14}, ResyncInterval: time.Second}, nil)
	r.logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r.metrics = metrics.NewMetrics(prometheus.NewRegistry())
	const logID = "0123456789abcdef0123456789abcdef"
	bad := decodeActiveLog(t, `{"logIdHex32":"`+logID+`","mmrStart":"0","mmrEnd":"042"}`)
	good := decodeActiveLog(t, `{"logIdHex32":"`+logID+`","mmrStart":"0","mmrEnd":"42"}`)

	r.checkAndReseal(context.Background(), bad)
	r.checkAndReseal(context.Background(), bad)
	if n := countLogLines(buf.String(), "WARN", "malformed range hint"); n != 1 {
		t.Fatalf("WARN lines after two ticks = %d, want 1", n)
	}
	if n := countLogLines(buf.String(), "DEBUG", "malformed range hint"); n != 1 {
		t.Fatalf("DEBUG lines after two ticks = %d, want 1", n)
	}
	if got := testutil.ToFloat64(r.metrics.ResyncMalformedHintTotal); got != 2 {
		t.Fatalf("sealer_resync_malformed_hint_total = %v, want 2", got)
	}

	r.checkAndReseal(context.Background(), good)
	r.checkAndReseal(context.Background(), bad)
	if n := countLogLines(buf.String(), "WARN", "malformed range hint"); n != 2 {
		t.Fatalf("WARN lines after the hint recovered and broke again = %d, want 2", n)
	}
}

func countLogLines(out, level, msg string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `"level":"`+level+`"`) && strings.Contains(line, msg) {
			n++
		}
	}
	return n
}

func decodeActiveLog(t *testing.T, row string) activeLog {
	t.Helper()
	var lg activeLog
	if err := json.Unmarshal([]byte(row), &lg); err != nil {
		t.Fatalf("decode %s: %v", row, err)
	}
	return lg
}

// TestActiveLogRangeDecode pins the coordinator wire contract for the range
// hint: canonical decimal strings or null, because a JSON number cannot carry
// an index above 2^53 exactly. Every other shape decodes without failing the
// page and marks the row malformed.
func TestActiveLogRangeDecode(t *testing.T) {
	ok := []struct {
		raw     string
		want    uint64
		present bool
	}{
		{`"0"`, 0, true},
		{`"42"`, 42, true},
		{`"4294967297"`, 1<<32 + 1, true},
		{`"9007199254740993"`, 1<<53 + 1, true},
		{`"18446744073709551615"`, math.MaxUint64, true},
		{`null`, 0, false},
	}
	for _, c := range ok {
		lg := decodeActiveLog(t, `{"logIdHex32":"x","mmrStart":"0","mmrEnd":`+c.raw+`}`)
		if err := lg.rangeErr(); err != nil {
			t.Fatalf("mmrEnd %s: unexpected error %v", c.raw, err)
		}
		got, present := lg.MmrEnd.Value()
		if present != c.present || got != c.want {
			t.Fatalf("mmrEnd %s: got (%d,%v) want (%d,%v)", c.raw, got, present, c.want, c.present)
		}
	}

	absent := decodeActiveLog(t, `{"logIdHex32":"x"}`)
	if err := absent.rangeErr(); err != nil {
		t.Fatalf("absent range: unexpected error %v", err)
	}
	if _, present := absent.MmrEnd.Value(); present {
		t.Fatal("absent mmrEnd must decode as not present")
	}

	malformed := []string{
		`""`, `"01"`, `"00"`, `"-1"`, `"+1"`, `" 1"`, `"1 "`, `"1.0"`, `"1e3"`,
		`"0x10"`, `"18446744073709551616"`, `"99999999999999999999"`,
		`42`, `4.2`, `true`, `{}`, `[]`,
	}
	for _, raw := range malformed {
		lg := decodeActiveLog(t, `{"logIdHex32":"x","mmrStart":"0","mmrEnd":`+raw+`}`)
		if lg.rangeErr() == nil {
			t.Fatalf("mmrEnd %s: expected malformed", raw)
		}
		if _, present := lg.MmrEnd.Value(); present {
			t.Fatalf("mmrEnd %s: malformed value must not be present", raw)
		}
		lg = decodeActiveLog(t, `{"logIdHex32":"x","mmrStart":`+raw+`,"mmrEnd":"0"}`)
		if lg.rangeErr() == nil {
			t.Fatalf("mmrStart %s: expected malformed", raw)
		}
	}
}

// TestResolveHeightNegativeCacheSkipsProbe pins R3: within the negative-cache
// backoff window resolveHeight must not touch R2 and must report a miss.
func TestResolveHeightNegativeCacheSkipsProbe(t *testing.T) {
	r, lister := newTestResyncManager(Config{ResyncMassifHeights: []uint8{14}, ResyncInterval: 30 * time.Second}, nil)
	const logID = "0123456789abcdef0123456789abcdef"
	logIDBytes := make([]byte, 16)
	r.heightMiss[logID] = time.Now().Add(1 * time.Hour) // still backed off

	if _, ok := r.resolveHeight(context.Background(), logID, logIDBytes); ok {
		t.Fatal("resolveHeight should report a miss within the backoff window")
	}
	if n := lister.calls(); n != 0 {
		t.Fatalf("resolveHeight should not probe R2 within the backoff window, got %d LISTs", n)
	}
}

// TestHeadMMRSizeFromObjectSize_MatchesRangeCount pins the resync freshness
// arithmetic to go-merklelog's own MassifContext.RangeCount, so a future change
// to the on-disk layout is caught here rather than silently mis-sizing heads.
func TestHeadMMRSizeFromObjectSize_MatchesRangeCount(t *testing.T) {
	const height = uint8(14)
	for _, massifIndex := range []uint32{0, 1, 5, 42} {
		for _, leaves := range []uint64{0, 1, 100, 8191} {
			// Build a real massif context at this height/index and give it a Data
			// buffer sized for `leaves` log entries — RangeCount reads only the
			// header fields and len(Data).
			mc := massifs.MassifContext{
				Start: massifs.MassifStart{
					Version:      massifs.MassifCurrentVersion,
					MassifHeight: height,
					MassifIndex:  massifIndex,
					FirstIndex:   massifs.MassifFirstLeaf(height, massifIndex),
				},
			}
			objectSize := mc.LogStart() + leaves*massifs.LogEntryBytes
			mc.Data = make([]byte, objectSize)

			want := mc.RangeCount()
			got := headMMRSizeFromObjectSize(height, massifIndex, int64(objectSize))
			if got != want {
				t.Fatalf("height=%d idx=%d leaves=%d: got %d, RangeCount %d",
					height, massifIndex, leaves, got, want)
			}
		}
	}
}

func TestHeadMMRSizeFromObjectSize_HeaderOnly(t *testing.T) {
	// A header-only object (no log entries) sizes to the massif's first index.
	const height = uint8(14)
	const idx = uint32(3)
	mc := massifs.MassifContext{Start: massifs.MassifStart{
		Version: massifs.MassifCurrentVersion, MassifHeight: height,
	}}
	got := headMMRSizeFromObjectSize(height, idx, int64(mc.LogStart()))
	if want := massifs.MassifFirstLeaf(height, idx); got != want {
		t.Fatalf("header-only: got %d want %d", got, want)
	}
}

func TestParseMassifHeights(t *testing.T) {
	cases := []struct {
		in   string
		want []uint8
	}{
		{"", nil},
		{"  ", nil},
		{"14", []uint8{14}},
		{"14,15", []uint8{14, 15}},
		{" 14 , 15 ", []uint8{14, 15}},
		{"14,14,15", []uint8{14, 15}}, // dedup
		{"0,14", []uint8{14}},         // zero skipped
		{"bad,14,", []uint8{14}},      // junk skipped
		{"bad", nil},
	}
	for _, c := range cases {
		got := parseMassifHeights(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("parseMassifHeights(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("parseMassifHeights(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestResyncEnabled(t *testing.T) {
	cases := []struct {
		heights []uint8
		url     string
		want    bool
	}{
		{nil, "https://c", false},
		{[]uint8{14}, "", false},
		{[]uint8{14}, "https://c", true},
	}
	for _, c := range cases {
		cfg := Config{ResyncMassifHeights: c.heights, CoordinatorRegisterURL: c.url}
		if got := cfg.ResyncEnabled(); got != c.want {
			t.Fatalf("ResyncEnabled(heights=%v url=%q) = %v, want %v", c.heights, c.url, got, c.want)
		}
	}
}

// TestActivePageDecode confirms the cursor is a nullable string: a JSON null
// terminates the walk (nil pointer), a string continues it.
func TestActivePageDecode(t *testing.T) {
	var end activePage
	if err := json.Unmarshal([]byte(`{"logs":[],"cursor":null}`), &end); err != nil {
		t.Fatal(err)
	}
	if end.Cursor != nil {
		t.Fatalf("null cursor should decode to nil, got %v", *end.Cursor)
	}

	var more activePage
	body := `{"logs":[{"logIdHex32":"0123456789abcdef0123456789abcdef","expiresAt":123,"mmrStart":"0","mmrEnd":"42"},` +
		`{"logIdHex32":"fedcba9876543210fedcba9876543210","expiresAt":123,"mmrStart":"0","mmrEnd":"042"}],"cursor":"abc"}`
	if err := json.Unmarshal([]byte(body), &more); err != nil {
		t.Fatal(err)
	}
	if more.Cursor == nil || *more.Cursor != "abc" {
		t.Fatalf("expected cursor 'abc', got %v", more.Cursor)
	}
	// One malformed row does not fail the page: both rows decode, and only
	// the second is marked malformed.
	if len(more.Logs) != 2 {
		t.Fatalf("unexpected logs decode: %+v", more.Logs)
	}
	if end, ok := more.Logs[0].MmrEnd.Value(); !ok || end != 42 || more.Logs[0].rangeErr() != nil {
		t.Fatalf("unexpected first row decode: %+v", more.Logs[0])
	}
	if more.Logs[1].rangeErr() == nil {
		t.Fatalf("expected the second row to be malformed: %+v", more.Logs[1])
	}
}
