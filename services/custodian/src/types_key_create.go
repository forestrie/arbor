package custodian

// CreateKeyRequest is the CBOR body for POST /api/keys.
type CreateKeyRequest struct {
	KeyOwnerID string `cbor:"keyOwnerId"`
	// SelfLogID is required: 32 lowercase hex digits (optional hyphens / 0x); KMS CryptoKey id is that hex.
	SelfLogID string            `cbor:"selfLogId"`
	Alg       string            `cbor:"alg,omitempty"`
	Labels    map[string]string `cbor:"labels,omitempty"`
	// ProtectionLevel: "SOFTWARE" or "HSM"; defaults to "SOFTWARE".
	ProtectionLevel string `cbor:"protectionLevel,omitempty"`
}

// CreateKeyResponse is the CBOR body for POST /api/keys success.
type CreateKeyResponse struct {
	KeyID     string `cbor:"keyId"`
	PublicKey string `cbor:"publicKey,omitempty"`
	Alg       string `cbor:"alg,omitempty"`
}
