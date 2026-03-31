package custodian

// CreateKeyRequest is the CBOR body for POST /api/keys.
type CreateKeyRequest struct {
	KeyOwnerID string `cbor:"keyOwnerId"`
	// SelfLogID is required: RFC-4122 UUID; the KMS CryptoKey id is that UUID
	// with hyphens removed (32 lowercase hex digits).
	SelfLogID string            `cbor:"selfLogId"`
	Alg       string            `cbor:"alg,omitempty"`
	Labels    map[string]string `cbor:"labels,omitempty"`
}

// CreateKeyResponse is the CBOR body for POST /api/keys success.
type CreateKeyResponse struct {
	KeyID     string `cbor:"keyId"`
	PublicKey string `cbor:"publicKey,omitempty"`
	Alg       string `cbor:"alg,omitempty"`
}
