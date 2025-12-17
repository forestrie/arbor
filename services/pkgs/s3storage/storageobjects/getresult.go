package storageobjects

// GetResult captures the response from a GetObject operation.
type GetResult struct {
	Data []byte
	ETag string
}


