package univocity

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestMockChain_RootLogId_ZeroAndNonZero satisfies plan §8.2 verification:
// unit test with mock for rootLogId returning zero vs non-zero.
func TestMockChain_RootLogId_ZeroAndNonZero(t *testing.T) {
	ctx := context.Background()
	zero := &mockChain{rootLogId: [32]byte{}}
	got, err := zero.RootLogId(ctx)
	if err != nil {
		t.Fatalf("RootLogId: %v", err)
	}
	if got != [32]byte{} {
		t.Error("expected zero rootLogId")
	}
	nonZero := &mockChain{rootLogId: [32]byte{31: 1}}
	got, err = nonZero.RootLogId(ctx)
	if err != nil {
		t.Fatalf("RootLogId: %v", err)
	}
	if got == [32]byte{} {
		t.Error("expected non-zero rootLogId")
	}
}

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

func TestContractClients_UnknownChain(t *testing.T) {
	pool, err := NewContractClients(map[uint64]string{84532: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = pool.Reader(1, common.HexToAddress("0x1"))
	if err != ErrChainNotConfigured {
		t.Fatalf("expected ErrChainNotConfigured, got %v", err)
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
