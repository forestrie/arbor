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
//
// SeqLo, SeqHi and LeaseExpiry echo the pulled LogGroup and the pull's
// lease. The DO marks only the rows that pull leased, and refuses the ack
// (409, nothing marked) unless exactly Limit of them are still pending under
// that lease, e.g. after a re-pull past the visibility timeout (FOR-655).
//
// MassifHeight is the one-based height the committer writes massifs at: a
// massif holds 2^(h-1) leaves (urkle.LeafCountForMassifHeight). The DO stores
// no massif index; readers derive it with the equivalent of
// massifs.MassifIndexFromLeafIndex. The DO uses MassifHeight only to size how
// many sequenced entries it retains.
type AckRequest struct {
	LogId          []byte `cbor:"logId"`
	SeqLo          uint64 `cbor:"seqLo"`
	SeqHi          uint64 `cbor:"seqHi"`
	LeaseExpiry    uint64 `cbor:"leaseExpiry"`
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
	return canonicalCBOR.Marshal(req)
}

// DecodeAckResponse decodes a CBOR ack response.
func DecodeAckResponse(data []byte) (*AckResponse, error) {
	var resp AckResponse
	if err := cbor.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal ack response: %w", err)
	}
	return &resp, nil
}
