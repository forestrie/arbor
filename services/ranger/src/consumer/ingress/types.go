// Package ingress provides types and functions for consuming entries from the
// forestrie-ingress Durable Object queue.
//
// The DO queue replaces the Cloudflare Queue-based ingress path, providing
// domain-aware batching by logId and limit-based acknowledgement.
//
// See: arbor/docs/arc-cloudflare-do-ingress.md
package ingress

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// PullRequest is sent to POST /queue/pull.
type PullRequest struct {
	PollerId     string `cbor:"pollerId"`
	BatchSize    int    `cbor:"batchSize"`
	VisibilityMs int    `cbor:"visibilityMs"`
}

// PullResponse is returned from POST /queue/pull.
// Wire format is a positional CBOR array: [version, leaseExpiry, logGroups].
type PullResponse struct {
	Version     uint
	LeaseExpiry uint64
	LogGroups   []LogGroup
}

// LogGroup contains entries for a single log, pre-grouped by the DO.
// Wire format: [logId, seqLo, seqHi, entries].
type LogGroup struct {
	LogId   []byte
	SeqLo   uint64
	SeqHi   uint64
	Entries []Entry
}

// Entry represents a single queue entry.
// Wire format: [contentHash, extra0, extra1, extra2, extra3].
type Entry struct {
	ContentHash []byte
	Extra0      []byte // may be nil
	Extra1      []byte
	Extra2      []byte
	Extra3      []byte
}

// AckRequest is sent to POST /queue/ack.
// Uses limit-based ack because seq values are non-contiguous per-log.
// See: arbor/docs/arc-cloudflare-do-ingress.md section 2.3
type AckRequest struct {
	LogId []byte `cbor:"logId"`
	SeqLo uint64 `cbor:"seqLo"`
	Limit uint64 `cbor:"limit"`
}

// AckResponse is returned from POST /queue/ack.
type AckResponse struct {
	Deleted int `cbor:"deleted"`
}

// DecodePullResponse decodes a CBOR pull response from the DO.
// The response uses positional arrays for efficiency:
//
//	[version, leaseExpiry, [[logId, seqLo, seqHi, [[contentHash, e0, e1, e2, e3], ...]], ...]]
func DecodePullResponse(data []byte) (*PullResponse, error) {
	var raw []any
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal pull response: %w", err)
	}

	if len(raw) < 3 {
		return nil, fmt.Errorf("invalid pull response: expected 3 elements, got %d", len(raw))
	}

	resp := &PullResponse{}

	// Version (uint)
	switch v := raw[0].(type) {
	case uint64:
		resp.Version = uint(v)
	case int64:
		resp.Version = uint(v)
	default:
		return nil, fmt.Errorf("invalid version type: %T", raw[0])
	}

	// LeaseExpiry (uint64)
	switch v := raw[1].(type) {
	case uint64:
		resp.LeaseExpiry = v
	case int64:
		resp.LeaseExpiry = uint64(v)
	default:
		return nil, fmt.Errorf("invalid leaseExpiry type: %T", raw[1])
	}

	// LogGroups (array)
	groupsRaw, ok := raw[2].([]any)
	if !ok {
		return nil, fmt.Errorf("invalid logGroups type: %T", raw[2])
	}

	resp.LogGroups = make([]LogGroup, len(groupsRaw))
	for i, g := range groupsRaw {
		group, err := decodeLogGroup(g)
		if err != nil {
			return nil, fmt.Errorf("decode logGroup[%d]: %w", i, err)
		}
		resp.LogGroups[i] = group
	}

	return resp, nil
}

func decodeLogGroup(raw any) (LogGroup, error) {
	arr, ok := raw.([]any)
	if !ok {
		return LogGroup{}, fmt.Errorf("invalid logGroup type: %T", raw)
	}
	if len(arr) < 4 {
		return LogGroup{}, fmt.Errorf("invalid logGroup: expected 4 elements, got %d", len(arr))
	}

	group := LogGroup{}

	// logId (bytes)
	group.LogId = toBytes(arr[0])
	if group.LogId == nil {
		return LogGroup{}, fmt.Errorf("invalid logId type: %T", arr[0])
	}

	// seqLo (uint64)
	switch v := arr[1].(type) {
	case uint64:
		group.SeqLo = v
	case int64:
		group.SeqLo = uint64(v)
	default:
		return LogGroup{}, fmt.Errorf("invalid seqLo type: %T", arr[1])
	}

	// seqHi (uint64)
	switch v := arr[2].(type) {
	case uint64:
		group.SeqHi = v
	case int64:
		group.SeqHi = uint64(v)
	default:
		return LogGroup{}, fmt.Errorf("invalid seqHi type: %T", arr[2])
	}

	// entries (array)
	entriesRaw, ok := arr[3].([]any)
	if !ok {
		return LogGroup{}, fmt.Errorf("invalid entries type: %T", arr[3])
	}

	group.Entries = make([]Entry, len(entriesRaw))
	for i, e := range entriesRaw {
		entry, err := decodeEntry(e)
		if err != nil {
			return LogGroup{}, fmt.Errorf("decode entry[%d]: %w", i, err)
		}
		group.Entries[i] = entry
	}

	return group, nil
}

func decodeEntry(raw any) (Entry, error) {
	arr, ok := raw.([]any)
	if !ok {
		return Entry{}, fmt.Errorf("invalid entry type: %T", raw)
	}
	if len(arr) < 5 {
		return Entry{}, fmt.Errorf("invalid entry: expected 5 elements, got %d", len(arr))
	}

	entry := Entry{
		ContentHash: toBytes(arr[0]),
		Extra0:      toBytesOrNil(arr[1]),
		Extra1:      toBytesOrNil(arr[2]),
		Extra2:      toBytesOrNil(arr[3]),
		Extra3:      toBytesOrNil(arr[4]),
	}

	if entry.ContentHash == nil {
		return Entry{}, fmt.Errorf("invalid contentHash type: %T", arr[0])
	}

	return entry, nil
}

// toBytes converts a CBOR value to []byte. Returns nil if not a byte type.
func toBytes(v any) []byte {
	if b, ok := v.([]byte); ok {
		return b
	}
	return nil
}

// toBytesOrNil converts a CBOR value to []byte, returning nil for null values.
func toBytesOrNil(v any) []byte {
	if v == nil {
		return nil
	}
	return toBytes(v)
}

// EncodePullRequest encodes a pull request to CBOR.
func EncodePullRequest(req PullRequest) ([]byte, error) {
	return cbor.Marshal(req)
}

// EncodeAckRequest encodes an ack request to CBOR.
func EncodeAckRequest(req AckRequest) ([]byte, error) {
	return cbor.Marshal(req)
}

// DecodeAckResponse decodes a CBOR ack response.
func DecodeAckResponse(data []byte) (*AckResponse, error) {
	var resp AckResponse
	if err := cbor.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal ack response: %w", err)
	}
	return &resp, nil
}
