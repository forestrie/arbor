package storageobjects

// GetOptions controls read behaviour for GetObject. The semantics are
// shared across backends (R2, S3, etc.).
//
// RangeLength < 0 means "read to end" starting at RangeStart.
type GetOptions struct {
	RangeStart  int64
	RangeLength int64
}
