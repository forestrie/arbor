package signer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// KeySigner signs a digest with a key identified by KMS resource name.
// Digest must be 32 bytes (e.g. SHA-256). No private key material is exposed.
type KeySigner interface {
	// Sign signs digest with the key at keyID. keyID is the full KMS resource name.
	Sign(ctx context.Context, keyID string, digest []byte) (signature []byte, err error)
}

// DigestFromPayloadHash decodes a hex payload_hash (64 hex chars) into 32 bytes.
// Returns error if not 32 bytes after decode.
func DigestFromPayloadHash(hexHash string) ([]byte, error) {
	b, err := hex.DecodeString(hexHash)
	if err != nil {
		return nil, fmt.Errorf("payload_hash hex decode: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("payload_hash must be 32 bytes (64 hex chars), got %d", len(b))
	}
	return b, nil
}

// DigestFromPayload computes SHA-256 of the raw payload bytes.
func DigestFromPayload(payload []byte) []byte {
	h := sha256.Sum256(payload)
	return h[:]
}
