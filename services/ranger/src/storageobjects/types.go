package storageobjects

// ListObject represents metadata for an object returned from list operations.
//
// It is intentionally shaped to match the needs of the ranger storage layer
// and the existing backends. JSON struct tags are used by the R2 HTTP/JSON
// client for direct decoding; S3 backends populate these fields manually.
type ListObject struct {
	Key          string `json:"key,omitempty"`
	LastModified string `json:"uploaded,omitempty"`
	ETag         string `json:"etag,omitempty"`
	Size         int64  `json:"size,omitempty"`
}

// ListPage represents a page of objects returned from a list operation.
// It is shared between backend clients (R2, S3, etc.) and the storage layer
// to avoid redundant decoding and copying. JSON struct tags are used by the
// R2 HTTP/JSON client for direct decoding.
type ListPage struct {
	Objects               []ListObject `json:"objects,omitempty"`
	NextContinuationToken string       `json:"cursor,omitempty"`
	IsTruncated           bool         `json:"truncated,omitempty"`
}
