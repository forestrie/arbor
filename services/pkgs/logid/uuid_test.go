package logid

import (
	"testing"
)

func TestUUID_String_ParseRoundTrip(t *testing.T) {
	raw := UUID{0: 0xae, 1: 0xac, 15: 0xba}
	want := "aeac0000-0000-0000-0000-0000000000ba"
	if got := raw.String(); got != want {
		t.Fatalf("String: got %q want %q", got, want)
	}
	parsed, err := ParseUUIDString(want)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != raw {
		t.Fatalf("round-trip: got %x want %x", parsed, raw)
	}
}

func TestFromContractBytes32(t *testing.T) {
	var wire [32]byte
	copy(wire[16:], []byte{0xae, 0xac, 0xb6, 0xe7, 0x7e, 0x8c, 0x47, 0xde, 0x8e, 0xa3, 0xf0, 0x28, 0x9d, 0x20, 0x3d, 0xba})
	u := FromContractBytes32(wire)
	if u[0] != 0xae || u[15] != 0xba {
		t.Fatalf("uuid bytes: %x", u)
	}
	back := u.ToContractBytes32()
	if back != wire {
		t.Fatalf("contract round-trip: %x vs %x", back, wire)
	}
}

func TestPaddedWire32(t *testing.T) {
	u := UUID{15: 0x01}
	wire := u.ToPaddedWire32()
	if wire[31] != 0x01 || wire[0] != 0 {
		t.Fatalf("wire pad: %x", wire)
	}
	if FromPaddedWire32(wire[:]) != u {
		t.Fatal("from padded wire mismatch")
	}
}

func TestParseCanonicalSegment_RequiresDashes(t *testing.T) {
	u := UUID{15: 0x01}
	want := u.String()
	got, err := ParseCanonicalSegment(want)
	if err != nil || got != u {
		t.Fatalf("canonical: got %v %x", err, got)
	}
	if _, err := ParseCanonicalSegment("00000000000000000000000000000001"); err == nil {
		t.Fatal("expected hyphenless hex to be rejected")
	}
}

func TestParseSegment_RejectsHex64(t *testing.T) {
	hex64 := "00000000000000000000000000000000aeacb6e77e8c47de8ea3f0289d203dba"
	if _, err := ParseSegment(hex64); err != ErrAmbiguousLength {
		t.Fatalf("got err %v want ErrAmbiguousLength", err)
	}
}

func TestFromBytes(t *testing.T) {
	u := UUID{15: 0x42}
	wire := u.ToPaddedWire32()
	got, err := FromBytes(wire[:])
	if err != nil || got != u {
		t.Fatalf("from 32-byte wire: %v %x", err, got)
	}
	got, err = FromBytes(u[:])
	if err != nil || got != u {
		t.Fatalf("from 16-byte: %v %x", err, got)
	}
}

func TestParseIndexBody(t *testing.T) {
	body := []byte("550e8400-e29b-41d4-a716-446655440000")
	u, err := ParseIndexBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("got %s", u.String())
	}
}
