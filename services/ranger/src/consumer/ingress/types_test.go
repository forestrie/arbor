package ingress

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestDecodePullResponse_EmptyLogGroups(t *testing.T) {
	// [version=1, leaseExpiry=1234567890, logGroups=[]]
	data := mustCBOR(t, []any{uint64(1), uint64(1234567890), []any{}})

	resp, err := DecodePullResponse(data)
	if err != nil {
		t.Fatalf("DecodePullResponse: %v", err)
	}

	if resp.Version != 1 {
		t.Errorf("Version: got %d, want 1", resp.Version)
	}
	if resp.LeaseExpiry != 1234567890 {
		t.Errorf("LeaseExpiry: got %d, want 1234567890", resp.LeaseExpiry)
	}
	if len(resp.LogGroups) != 0 {
		t.Errorf("LogGroups: got %d, want 0", len(resp.LogGroups))
	}
}

func TestDecodePullResponse_SingleLogGroup(t *testing.T) {
	logId := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	contentHash := make([]byte, 32)
	for i := range contentHash {
		contentHash[i] = byte(i)
	}

	// Single entry: [contentHash, extra0, extra1, extra2, extra3]
	entry := []any{contentHash, nil, nil, nil, nil}

	// LogGroup: [logId, seqLo, seqHi, entries]
	group := []any{logId, uint64(100), uint64(100), []any{entry}}

	// Response: [version, leaseExpiry, logGroups]
	data := mustCBOR(t, []any{uint64(1), uint64(9999), []any{group}})

	resp, err := DecodePullResponse(data)
	if err != nil {
		t.Fatalf("DecodePullResponse: %v", err)
	}

	if len(resp.LogGroups) != 1 {
		t.Fatalf("LogGroups: got %d, want 1", len(resp.LogGroups))
	}

	g := resp.LogGroups[0]
	if !bytes.Equal(g.LogId, logId) {
		t.Errorf("LogId: got %x, want %x", g.LogId, logId)
	}
	if g.SeqLo != 100 {
		t.Errorf("SeqLo: got %d, want 100", g.SeqLo)
	}
	if g.SeqHi != 100 {
		t.Errorf("SeqHi: got %d, want 100", g.SeqHi)
	}
	if len(g.Entries) != 1 {
		t.Fatalf("Entries: got %d, want 1", len(g.Entries))
	}

	e := g.Entries[0]
	if !bytes.Equal(e.ContentHash, contentHash) {
		t.Errorf("ContentHash: got %x, want %x", e.ContentHash, contentHash)
	}
}

func TestDecodePullResponse_MultipleEntriesWithExtras(t *testing.T) {
	logId := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}

	hash1 := make([]byte, 32)
	hash2 := make([]byte, 32)
	for i := range hash1 {
		hash1[i] = byte(i)
		hash2[i] = byte(255 - i)
	}

	extra0 := []byte("extra0-data")

	entry1 := []any{hash1, extra0, nil, nil, nil}
	entry2 := []any{hash2, nil, nil, nil, nil}

	group := []any{logId, uint64(50), uint64(51), []any{entry1, entry2}}

	data := mustCBOR(t, []any{uint64(1), uint64(12345), []any{group}})

	resp, err := DecodePullResponse(data)
	if err != nil {
		t.Fatalf("DecodePullResponse: %v", err)
	}

	if len(resp.LogGroups) != 1 {
		t.Fatalf("LogGroups: got %d, want 1", len(resp.LogGroups))
	}

	g := resp.LogGroups[0]
	if len(g.Entries) != 2 {
		t.Fatalf("Entries: got %d, want 2", len(g.Entries))
	}

	if !bytes.Equal(g.Entries[0].ContentHash, hash1) {
		t.Errorf("Entry[0].ContentHash mismatch")
	}
	if !bytes.Equal(g.Entries[0].Extra0, extra0) {
		t.Errorf("Entry[0].Extra0: got %v, want %v", g.Entries[0].Extra0, extra0)
	}
	if !bytes.Equal(g.Entries[1].ContentHash, hash2) {
		t.Errorf("Entry[1].ContentHash mismatch")
	}
	if g.Entries[1].Extra0 != nil {
		t.Errorf("Entry[1].Extra0: got %v, want nil", g.Entries[1].Extra0)
	}
}

func TestDecodePullResponse_MultipleLogGroups(t *testing.T) {
	logId1 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	logId2 := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	hash := make([]byte, 32)

	entry := []any{hash, nil, nil, nil, nil}

	group1 := []any{logId1, uint64(10), uint64(11), []any{entry, entry}}
	group2 := []any{logId2, uint64(20), uint64(22), []any{entry, entry, entry}}

	data := mustCBOR(t, []any{uint64(1), uint64(5555), []any{group1, group2}})

	resp, err := DecodePullResponse(data)
	if err != nil {
		t.Fatalf("DecodePullResponse: %v", err)
	}

	if len(resp.LogGroups) != 2 {
		t.Fatalf("LogGroups: got %d, want 2", len(resp.LogGroups))
	}

	if !bytes.Equal(resp.LogGroups[0].LogId, logId1) {
		t.Errorf("LogGroups[0].LogId mismatch")
	}
	if len(resp.LogGroups[0].Entries) != 2 {
		t.Errorf("LogGroups[0].Entries: got %d, want 2", len(resp.LogGroups[0].Entries))
	}

	if !bytes.Equal(resp.LogGroups[1].LogId, logId2) {
		t.Errorf("LogGroups[1].LogId mismatch")
	}
	if len(resp.LogGroups[1].Entries) != 3 {
		t.Errorf("LogGroups[1].Entries: got %d, want 3", len(resp.LogGroups[1].Entries))
	}
}

func TestDecodePullResponse_InvalidFormat(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too few elements",
			data: mustCBOR(t, []any{uint64(1), uint64(2)}),
		},
		{
			name: "invalid version type",
			data: mustCBOR(t, []any{"not-a-number", uint64(2), []any{}}),
		},
		{
			name: "invalid logGroups type",
			data: mustCBOR(t, []any{uint64(1), uint64(2), "not-an-array"}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodePullResponse(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestEncodeAckRequest(t *testing.T) {
	req := AckRequest{
		LogId: []byte{0x01, 0x02, 0x03, 0x04},
		SeqLo: 100,
		Limit: 50,
	}

	data, err := EncodeAckRequest(req)
	if err != nil {
		t.Fatalf("EncodeAckRequest: %v", err)
	}

	// Decode and verify
	var decoded AckRequest
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !bytes.Equal(decoded.LogId, req.LogId) {
		t.Errorf("LogId: got %x, want %x", decoded.LogId, req.LogId)
	}
	if decoded.SeqLo != req.SeqLo {
		t.Errorf("SeqLo: got %d, want %d", decoded.SeqLo, req.SeqLo)
	}
	if decoded.Limit != req.Limit {
		t.Errorf("Limit: got %d, want %d", decoded.Limit, req.Limit)
	}
}

func TestEncodePullRequest(t *testing.T) {
	req := PullRequest{
		PollerId:     "test-poller-123",
		BatchSize:    100,
		VisibilityMs: 30000,
	}

	data, err := EncodePullRequest(req)
	if err != nil {
		t.Fatalf("EncodePullRequest: %v", err)
	}

	// Decode and verify
	var decoded PullRequest
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.PollerId != req.PollerId {
		t.Errorf("PollerId: got %q, want %q", decoded.PollerId, req.PollerId)
	}
	if decoded.BatchSize != req.BatchSize {
		t.Errorf("BatchSize: got %d, want %d", decoded.BatchSize, req.BatchSize)
	}
	if decoded.VisibilityMs != req.VisibilityMs {
		t.Errorf("VisibilityMs: got %d, want %d", decoded.VisibilityMs, req.VisibilityMs)
	}
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	data, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	return data
}
