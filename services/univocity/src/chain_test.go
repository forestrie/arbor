package univocity

import (
	"testing"
)

func TestLogIDFromHex_Valid32Bytes(t *testing.T) {
	hex := "0x0000000000000000000000000000000000000000000000000000000000000001"
	id, ok := LogIDFromHex(hex)
	if !ok {
		t.Fatal("LogIDFromHex failed")
	}
	got := LogIDToHex(id)
	if got != hex {
		t.Errorf("round-trip: got %q", got)
	}
}

func TestLogIDFromHex_WithoutPrefix(t *testing.T) {
	hex := "0000000000000000000000000000000000000000000000000000000000000001"
	id, ok := LogIDFromHex(hex)
	if !ok {
		t.Fatal("LogIDFromHex failed")
	}
	if LogIDToHex(id) != "0x"+hex {
		t.Error("expected 0x-prefixed")
	}
}

func TestLogIDFromHex_Invalid(t *testing.T) {
	if _, ok := LogIDFromHex("not-hex"); ok {
		t.Error("expected false for invalid hex")
	}
	if _, ok := LogIDFromHex("0xgg"); ok {
		t.Error("expected false for invalid hex chars")
	}
}

func TestLogKind_String(t *testing.T) {
	if LogKindAuthority.String() != "authority" {
		t.Errorf("got %q", LogKindAuthority.String())
	}
	if LogKindData.String() != "data" {
		t.Errorf("got %q", LogKindData.String())
	}
	if LogKindUndefined.String() != "undefined" {
		t.Errorf("got %q", LogKindUndefined.String())
	}
}
