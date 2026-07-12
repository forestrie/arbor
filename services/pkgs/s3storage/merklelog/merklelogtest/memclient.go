// Package merklelogtest provides test doubles for the merklelog storage
// layer. MemClient is an in-memory ObjectClient sufficient to drive the real
// Store / massifs append+commit paths in unit tests (no S3/R2/minio needed).
package merklelogtest

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/storageobjects"
)

type memObject struct {
	data []byte
	etag string
}

// MemClient is a thread-safe in-memory merklelog.ObjectClient.
//
// Contract fidelity that the storage layer depends on:
//   - ListObjects returns keys in lexicographic order (Store.HeadIndex takes
//     the LAST key of the final page as the head index) and honours
//     maxKeys + continuation paging.
//   - Missing GetObject keys map to massifstorage.ErrDoesNotExist via the
//     shared storageobjects error mapping (ErrLogEmpty detection).
//   - PutObject honours FailIfExists (ErrExistsOC) and IfMatch (ErrContentOC)
//     the way the S3/R2 backends map preconditions.
type MemClient struct {
	mu      sync.Mutex
	objects map[string]memObject
	etagSeq int
}

var _ merklelog.ObjectClient = (*MemClient)(nil)

// NewMemClient creates an empty in-memory object store.
func NewMemClient() *MemClient {
	return &MemClient{objects: make(map[string]memObject)}
}

// ListObjects lists keys with the given prefix in lexicographic order.
// continuation is the integer offset returned in NextContinuationToken.
func (c *MemClient) ListObjects(_ context.Context, prefix, continuation string, maxKeys int) (merklelog.ListPage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var keys []string
	for k := range c.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	start := 0
	if continuation != "" {
		n, err := strconv.Atoi(continuation)
		if err != nil {
			return merklelog.ListPage{}, fmt.Errorf("bad continuation token %q: %w", continuation, err)
		}
		start = n
	}
	if start > len(keys) {
		start = len(keys)
	}
	end := len(keys)
	if maxKeys > 0 && start+maxKeys < end {
		end = start + maxKeys
	}

	page := merklelog.ListPage{}
	for _, k := range keys[start:end] {
		o := c.objects[k]
		page.Objects = append(page.Objects, merklelog.ListObject{
			Key:  k,
			ETag: o.etag,
			Size: int64(len(o.data)),
		})
	}
	if end < len(keys) {
		page.IsTruncated = true
		page.NextContinuationToken = strconv.Itoa(end)
	}
	return page, nil
}

// GetObject returns the object (or the requested range of it).
func (c *MemClient) GetObject(_ context.Context, key string, opts merklelog.GetOptions) (merklelog.GetResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	o, ok := c.objects[key]
	if !ok {
		return merklelog.GetResult{}, storageobjects.MapGetError(http.StatusNotFound, fmt.Errorf("no such key %q", key))
	}

	// Range semantics per storageobjects.GetOptions: zero value = full object;
	// length > 0 = [start, start+length); length == 0 with start > 0 = 1-byte
	// probe; length < 0 = start to end.
	data := o.data
	if !(opts.RangeStart == 0 && opts.RangeLength == 0) {
		start := opts.RangeStart
		if start < 0 {
			start = 0
		}
		if start >= int64(len(data)) {
			return merklelog.GetResult{}, storageobjects.MapGetError(
				http.StatusRequestedRangeNotSatisfiable,
				fmt.Errorf("range start %d beyond object size %d for %q", start, len(data), key),
			)
		}
		end := int64(len(data))
		switch {
		case opts.RangeLength > 0:
			if start+opts.RangeLength < end {
				end = start + opts.RangeLength
			}
		case opts.RangeLength == 0: // start > 0 here: 1-byte probe
			end = start + 1
		}
		data = data[start:end]
	}

	out := make([]byte, len(data))
	copy(out, data)
	return merklelog.GetResult{Data: out, ETag: o.etag}, nil
}

// PutObject stores the object, honouring create-only and If-Match preconditions.
func (c *MemClient) PutObject(_ context.Context, key string, data []byte, opts merklelog.PutOptions) (merklelog.PutResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	existing, exists := c.objects[key]
	if opts.FailIfExists && exists {
		return merklelog.PutResult{}, storageobjects.MapPutError(http.StatusPreconditionFailed, true, fmt.Errorf("key %q exists", key))
	}
	if opts.IfNoneMatch == "*" && exists {
		return merklelog.PutResult{}, storageobjects.MapPutError(http.StatusPreconditionFailed, true, fmt.Errorf("key %q exists", key))
	}
	if opts.IfMatch != "" && (!exists || existing.etag != opts.IfMatch) {
		return merklelog.PutResult{}, storageobjects.MapPutError(http.StatusPreconditionFailed, false, fmt.Errorf("etag mismatch for %q", key))
	}

	c.etagSeq++
	stored := make([]byte, len(data))
	copy(stored, data)
	o := memObject{data: stored, etag: strconv.Itoa(c.etagSeq)}
	c.objects[key] = o
	return merklelog.PutResult{ETag: o.etag}, nil
}

// DeleteObject removes the key; deleting a missing key succeeds.
func (c *MemClient) DeleteObject(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.objects, key)
	return nil
}

// Keys returns all stored keys in lexicographic order (test assertions).
func (c *MemClient) Keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]string, 0, len(c.objects))
	for k := range c.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
