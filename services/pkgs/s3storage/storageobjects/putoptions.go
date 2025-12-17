package storageobjects

// PutOptions controls conditional write behaviour for PutObject.
//
// FailIfExists is a higher-level semantic used by the storage layer and
// interpreted by backends when mapping HTTP/S3 status codes.
type PutOptions struct {
	ContentType  string
	IfMatch      string
	IfNoneMatch  string
	FailIfExists bool
}


