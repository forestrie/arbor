package consumer

import (
	"strings"
	"testing"
)

func TestParseV2MassifDataObjectKey(t *testing.T) {
	key := "v2/merklelog/massifs/14/de305d54-75b4-431b-adb2-eb6b9e546014/0000000000000042.log"
	h, logID, idx, ok, err := parseV2MassifDataObjectKey(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if h != 14 {
		t.Fatalf("expected height 14, got %d", h)
	}
	if idx != 42 {
		t.Fatalf("expected index 42, got %d", idx)
	}

	// Key derivation uses the UUID string form.
	contentHex := strings.Repeat("ab", 32) // 64 hex chars
	gotKey, err := receiptCacheKeyV1(logID, contentHex)
	if err != nil {
		t.Fatalf("receiptCacheKeyV1: %v", err)
	}
	wantKey := "ranger/v1/de305d54-75b4-431b-adb2-eb6b9e546014/latest/" + contentHex
	if gotKey != wantKey {
		t.Fatalf("key mismatch:\n got: %s\nwant: %s", gotKey, wantKey)
	}
}

func TestParseV2MassifDataObjectKey_IgnoresNonMassifKeys(t *testing.T) {
	key := "v2/merklelog/checkpoints/14/de305d54-75b4-431b-adb2-eb6b9e546014/0000000000000042.sth"
	_, _, _, ok, err := parseV2MassifDataObjectKey(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false for non-massif key")
	}
}
