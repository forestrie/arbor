package custodian

// CreateKeyRequest is the CBOR body for POST /api/keys.
type CreateKeyRequest struct {
	KeyOwnerID string            `cbor:"keyOwnerId"`
	Alg        string            `cbor:"alg,omitempty"`
	Labels     map[string]string `cbor:"labels,omitempty"`
}

// CreateKeyResponse is the CBOR body for POST /api/keys success.
type CreateKeyResponse struct {
	KeyID     string `cbor:"keyId"`
	PublicKey string `cbor:"publicKey,omitempty"`
	Alg       string `cbor:"alg,omitempty"`
}
