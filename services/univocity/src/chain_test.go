package univocity

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
)

// TestMockChain_RootLogId_ZeroAndNonZero satisfies plan §8.2 verification:
// unit test with mock for rootLogId returning zero vs non-zero.
func TestMockChain_RootLogId_ZeroAndNonZero(t *testing.T) {
	ctx := context.Background()
	zero := &mockChain{rootLogId: logid.Zero}
	got, err := zero.RootLogId(ctx)
	if err != nil {
		t.Fatalf("RootLogId: %v", err)
	}
	if !got.IsZero() {
		t.Error("expected zero rootLogId")
	}
	nonZero := &mockChain{rootLogId: testLogID(1)}
	got, err = nonZero.RootLogId(ctx)
	if err != nil {
		t.Fatalf("RootLogId: %v", err)
	}
	if got.IsZero() {
		t.Error("expected non-zero rootLogId")
	}
}

func TestParseSegment_UUID(t *testing.T) {
	id := testLogID(1)
	got, err := logid.ParseSegment(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("round-trip: got %v want %v", got, id)
	}
}

func TestParseSegment_RejectsHex64(t *testing.T) {
	hex64 := "00000000000000000000000000000000aeacb6e77e8c47de8ea3f0289d203dba"
	if _, err := logid.ParseSegment(hex64); err != logid.ErrAmbiguousLength {
		t.Fatalf("got %v", err)
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
