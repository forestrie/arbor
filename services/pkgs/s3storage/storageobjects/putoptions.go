package storageobjects

// PutOptions controls conditional write behaviour for PutObject.
//
// FailIfExists is a higher-level semantic used by the storage layer and
// interpreted by backends when mapping HTTP/S3 status codes.
type PutOptions struct {
	ContentType string
	IfMatch     string
	IfNoneMatch string
	// CacheControl is published as the object's Cache-Control response header.
	// Empty means the backend sends none, which leaves the CDN to apply
	// heuristic caching — see merklelog.CacheControlForObject (ADR-0057) for
	// why log objects must always state a directive.
	CacheControl string
	FailIfExists bool
}
