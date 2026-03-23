package custodian

// DeleteKeyVersionsFromRequest is the CBOR body for POST /api/keys/{keyId}/versions/delete-from.
type DeleteKeyVersionsFromRequest struct {
	Version int `cbor:"version"`
}

// DeleteKeyResponse is the CBOR body for delete operations.
type DeleteKeyResponse struct {
	KeyID          string `cbor:"keyId"`
	DestroyedCount int    `cbor:"destroyedCount"`
}
