package signer

import (
	"context"
	"encoding/hex"
	"testing"
)

func TestDigestFromPayloadHash_Valid(t *testing.T) {
	d := make([]byte, 32)
	d[0] = 0xab
	got, err := DigestFromPayloadHash(hex.EncodeToString(d))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 32 || got[0] != 0xab {
		t.Errorf("expected 32 bytes with 0xab first, got %x", got)
	}
}

func TestDigestFromPayloadHash_InvalidLength(t *testing.T) {
	_, err := DigestFromPayloadHash(hex.EncodeToString([]byte{1, 2, 3}))
	if err == nil {
		t.Fatal("expected error for non-32-byte hash")
	}
}

func TestDigestFromPayloadHash_InvalidHex(t *testing.T) {
	_, err := DigestFromPayloadHash("not-hex!!!")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestDigestFromPayload(t *testing.T) {
	payload := []byte("hello")
	got := DigestFromPayload(payload)
	if len(got) != 32 {
		t.Errorf("expected 32-byte digest, got %d", len(got))
	}
	// SHA256 of "hello" is deterministic
	got2 := DigestFromPayload(payload)
	if hex.EncodeToString(got) != hex.EncodeToString(got2) {
		t.Error("DigestFromPayload not deterministic")
	}
}

func TestMockKeySigner_Sign(t *testing.T) {
	m := &mockKeySigner{signature: []byte("x")}
	sig, err := m.Sign(context.Background(), "key", make([]byte, 32))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(sig) != "x" {
		t.Errorf("expected signature x, got %q", sig)
	}
}
