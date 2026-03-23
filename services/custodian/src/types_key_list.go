package custodian

// KeyListEntry is one key in a list result.
type KeyListEntry struct {
	KeyID   string `cbor:"keyId"`
	Version int    `cbor:"version"`
	Count   *int   `cbor:"count,omitempty"`
}

// ListKeysRequest is the CBOR body for POST /api/keys/list.
type ListKeysRequest struct {
	Labels    map[string]string `cbor:"labels"`
	Predicate string            `cbor:"predicate,omitempty"`
}

// ListKeysResponse is the CBOR body for POST /api/keys/list success.
type ListKeysResponse struct {
	Keys []KeyListEntry `cbor:"keys"`
}
