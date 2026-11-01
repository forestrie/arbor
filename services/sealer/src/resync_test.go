package sealer

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/forestrie/go-merklelog/massifs"
)

// newTestResyncManager builds a manager with no S3 client — safe only for paths
// that short-circuit before any R2 access (cursor reset, hint fast-path,
// negative-cache skip).
func newTestResyncManager(cfg Config, httpClient *HTTPClient) *ResyncManager {
	return &ResyncManager{
		cfg:         cfg,
		httpClient:  httpClient,
		logger:      slog.Default(),
		heightByLog: map[string]uint8{},
		heightMiss:  map[string]time.Time{},
		sealedByLog: map[string]uint64{},
		factories:   nil,
	}
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
	r := newTestResyncManager(cfg, NewHTTPClient(slog.Default()))
	r.cursor = "eyJzIjozLCJrIjoiZmYifQ" // a stale opaque cursor

	r.tick(context.Background())

	if r.cursor != "" {
		t.Fatalf("cursor should reset to \"\" on fetch error, got %q", r.cursor)
	}
}

// TestHintFastPathSkipsWhenSealedCoversMmrEnd pins R4: when the cached sealed
// size already covers the furthest authorized index, checkAndReseal returns
// without any R2 access (s3Client is nil, so a fall-through would panic).
func TestHintFastPathSkipsWhenSealedCoversMmrEnd(t *testing.T) {
	r := newTestResyncManager(Config{ResyncMassifHeights: []uint8{14}}, nil)
	const logID = "0123456789abcdef0123456789abcdef"
	r.sealedByLog[logID] = 100

	// No panic (no S3 touched) and it returns quickly => fast-path taken.
	r.checkAndReseal(context.Background(), decodeActiveLog(t, `{"logIdHex32":"`+logID+`","mmrStart":"0","mmrEnd":"50"}`))
}

// TestHintFastPathAtMaxUint64 pins the fast path at the top of the uint64
// range (plan-2611-01): an mmrEnd of 2^64-1 arrives as a decimal string and
// compares exactly against the cached sealed size.
func TestHintFastPathAtMaxUint64(t *testing.T) {
	r := newTestResyncManager(Config{ResyncMassifHeights: []uint8{14}}, nil)
	const logID = "0123456789abcdef0123456789abcdef"
	r.sealedByLog[logID] = math.MaxUint64

	r.checkAndReseal(context.Background(), decodeActiveLog(t,
		`{"logIdHex32":"`+logID+`","mmrStart":"18446744073709551614","mmrEnd":"18446744073709551615"}`))
}

// TestCheckAndResealSkipsMalformedRangeHint pins the per-log handling of a
// malformed range value: the row is skipped like a row with an invalid
// logId — no R2 access (s3Client is nil, so a fall-through would panic) —
// and the rest of the page is unaffected.
func TestCheckAndResealSkipsMalformedRangeHint(t *testing.T) {
	r := newTestResyncManager(Config{ResyncMassifHeights: []uint8{14}}, nil)
	const logID = "0123456789abcdef0123456789abcdef"
	for _, row := range []string{
		`{"logIdHex32":"` + logID + `","mmrStart":"0","mmrEnd":"042"}`,
		`{"logIdHex32":"` + logID + `","mmrStart":42,"mmrEnd":"50"}`,
		`{"logIdHex32":"` + logID + `","mmrStart":"0","mmrEnd":"18446744073709551616"}`,
	} {
		r.checkAndReseal(context.Background(), decodeActiveLog(t, row))
	}
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
// hint (plan-2611-01 D1): canonical decimal strings or null. Every other
// shape decodes without failing the page and marks the row malformed.
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
// backoff window resolveHeight must not touch S3 (s3Client is nil) and must
// report a miss.
func TestResolveHeightNegativeCacheSkipsProbe(t *testing.T) {
	r := newTestResyncManager(Config{ResyncMassifHeights: []uint8{14}, ResyncInterval: 30 * time.Second}, nil)
	const logID = "0123456789abcdef0123456789abcdef"
	logIDBytes := make([]byte, 16)
	r.heightMiss[logID] = time.Now().Add(1 * time.Hour) // still backed off

	if _, ok := r.resolveHeight(context.Background(), logID, logIDBytes); ok {
		t.Fatal("resolveHeight should report a miss within the backoff window")
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
