package custodian

// CuratorLogKeyResponse is the CBOR body for GET /api/keys/curator/log-key.
type CuratorLogKeyResponse struct {
	KeyID string `cbor:"keyId"`
}
