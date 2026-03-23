package custodian

// PublicKeyResponse is the CBOR body for GET /api/keys/{keyId}/public.
type PublicKeyResponse struct {
	KeyID     string `cbor:"keyId"`
	PublicKey string `cbor:"publicKey"`
	Alg       string `cbor:"alg"`
}
