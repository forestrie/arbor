package ingress

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// AckRequest is sent to POST /queue/ack.
// Uses limit-based ack because seq values are non-contiguous per-log.
// See: arbor/docs/arc-cloudflare-do-ingress.md section 2.3
//
// With return path unification (Phase 9), ack also records leaf indices
// to enable direct registration status queries from the DO.
// massifIndex is derived: floor(leafIndex / (1 << massifHeight))
type AckRequest struct {
	LogId          []byte `cbor:"logId"`
	SeqLo          uint64 `cbor:"seqLo"`
	Limit          uint64 `cbor:"limit"`
	FirstLeafIndex uint64 `cbor:"firstLeafIndex"`
	MassifHeight   uint64 `cbor:"massifHeight"`
}

// AckResponse is returned from POST /queue/ack.
type AckResponse struct {
	Acked int `cbor:"acked"`
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
