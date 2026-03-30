package custodian

import (
	"crypto/sha256"
	"fmt"
)

// SignRequest is the CBOR body for POST /api/keys/{keyId}/sign.
// Exactly one of PayloadHash or Payload must be non-empty.
type SignRequest struct {
	PayloadHash []byte `cbor:"payloadHash,omitempty"`
	Payload     []byte `cbor:"payload,omitempty"`
	// RawSignatureOnly requests a CBOR body { signature: bstr } with IEEE P1363 r‖s
	// (64 bytes for ES256 / ES256K) over the same digest, instead of custodian COSE_Sign1.
	RawSignatureOnly bool `cbor:"rawSignatureOnly,omitempty"`
}

// RawSignResponse is the successful body for POST /api/keys/{keyId}/sign when RawSignatureOnly is true.
type RawSignResponse struct {
	Signature []byte `cbor:"signature"`
}

// DigestFromSignRequest returns the 32-byte SHA-256 digest committed in the COSE payload.
func DigestFromSignRequest(req *SignRequest) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}
	hasHash := len(req.PayloadHash) > 0
	hasPayload := len(req.Payload) > 0
	if hasHash && hasPayload {
		return nil, fmt.Errorf("provide exactly one of payloadHash or payload")
	}
	if hasHash {
		if len(req.PayloadHash) != 32 {
			return nil, fmt.Errorf("payloadHash must be 32 bytes, got %d", len(req.PayloadHash))
		}
		out := make([]byte, 32)
		copy(out, req.PayloadHash)
		return out, nil
	}
	if hasPayload {
		sum := sha256.Sum256(req.Payload)
		return sum[:], nil
	}
	return nil, fmt.Errorf("provide payloadHash or payload")
}
