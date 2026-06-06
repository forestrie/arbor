package custodian

// EnsureKeyRequest is the CBOR body for POST /api/keys (ensure custody key).
type EnsureKeyRequest struct {
	KeyOwnerID string `cbor:"keyOwnerId"`
	// SelfLogID is required: 32 lowercase hex digits (optional hyphens / 0x); KMS CryptoKey id is that hex.
	SelfLogID string            `cbor:"selfLogId"`
	Alg       string            `cbor:"alg,omitempty"`
	Labels    map[string]string `cbor:"labels,omitempty"`
	// ProtectionLevel: "SOFTWARE" or "HSM"; defaults to "SOFTWARE".
	ProtectionLevel string `cbor:"protectionLevel,omitempty"`
}

// EnsureKeyResponse is the CBOR body for POST /api/keys success.
type EnsureKeyResponse struct {
	KeyID     string `cbor:"keyId"`
	PublicKey string `cbor:"publicKey,omitempty"`
	Alg       string `cbor:"alg,omitempty"`
	// Created is true when KMS CreateCryptoKey ran; false when the key already existed.
	Created bool `cbor:"created,omitempty"`
}
