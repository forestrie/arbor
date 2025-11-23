package storage

import (
	"context"

	storageobjects "github.com/forestrie/arbor/services/ranger/storageobjects"
)

// ListObject and ListPage are aliases to the shared storageobjects types so
// that backends can decode directly into the common representation without
// requiring additional copying.
type ListObject = storageobjects.ListObject
type ListPage = storageobjects.ListPage

// GetOptions, GetResult, PutOptions, and PutResult are also aliases to shared
// storageobjects types so that all backends and the storage layer agree on a
// single representation.
type GetOptions = storageobjects.GetOptions
type GetResult = storageobjects.GetResult
type PutOptions = storageobjects.PutOptions
type PutResult = storageobjects.PutResult

// ObjectClient is a backend-agnostic interface for minimal blob operations
// required by the storage layer.
type ObjectClient interface {
	ListObjects(ctx context.Context, prefix, continuation string, maxKeys int) (ListPage, error)
	GetObject(ctx context.Context, key string, opts GetOptions) (GetResult, error)
	PutObject(ctx context.Context, key string, data []byte, opts PutOptions) (PutResult, error)
	DeleteObject(ctx context.Context, key string) error
}
