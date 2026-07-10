package storageobjects

// GetOptions controls read behaviour for GetObject. The semantics are shared
// across backends (S3-compatible APIs, R2 native APIs, etc.).
//
// Zero value (RangeStart == 0, RangeLength == 0) means read the whole object —
// no Range header. RangeLength > 0 reads that many bytes starting at RangeStart.
// RangeLength == 0 with RangeStart > 0 is a 1-byte probe at that offset.
// RangeLength < 0 means "read to end" starting at RangeStart (open-ended Range
// when RangeStart > 0; full object when RangeStart == 0).
type GetOptions struct {
	RangeStart  int64
	RangeLength int64
}
