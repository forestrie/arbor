package r2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/forestrie/arbor/services/pkgs/logredact"
	storageobjects "github.com/forestrie/arbor/services/pkgs/s3storage/storageobjects"
)

// HTTPDoer abstracts the subset of http.Client used by the R2 client.
// ranger.HTTPClient satisfies this interface.
type HTTPDoer interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// Client provides minimal helpers for interacting with Cloudflare R2 using the
// native HTTP/JSON API. Connection pooling is managed by the provided HTTPDoer
// implementation.
//
// NOTE: we intentionally keep this thin; consider introducing retries and
// richer telemetry if we observe transient failures at scale.
type Client struct {
	baseURL *url.URL
	token   string
	doer    HTTPDoer
	logger  *slog.Logger
}

// PutOptions controls conditional write behaviour for PUT requests.
// It is an alias of storageobjects.PutOptions so that callers can share a
// single representation across backends.
type PutOptions = storageobjects.PutOptions

// PutResult captures relevant response metadata from a PUT.
// It is an alias of storageobjects.PutResult.
type PutResult = storageobjects.PutResult

// ListResult represents a page of objects returned from ListObjects.
// It is an alias of storageobjects.ListPage so that callers in other
// packages can share a single decoded representation without additional
// copying.
type ListResult = storageobjects.ListPage

// ObjectSummary represents metadata for an object returned from list
// operations. It is an alias of storageobjects.ListObject.
type ObjectSummary = storageobjects.ListObject

// GetOptions controls read behaviour for GetObject.
// It is an alias of storageobjects.GetOptions.
type GetOptions = storageobjects.GetOptions

// GetResult captures the response from GetObject.
// It is an alias of storageobjects.GetResult.
type GetResult = storageobjects.GetResult

// Error represents an HTTP error returned by the R2 API.
type Error struct {
	StatusCode int
	Body       string
}

func (e *Error) Error() string {
	return fmt.Sprintf("r2 api error: status=%d body_sha256=%s", e.StatusCode, logredact.StringSHA256Hex(e.Body))
}

// emptyBodySHA256 is the SHA256 hash of an empty string, used for x-amz-content-sha256
// header on requests with no body (GET, DELETE, etc.)
const emptyBodySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// NewClient constructs a Client using the provided baseURL (typically R2_WRITE_URL) and bearer token.
func NewClient(baseURL, bearerToken string, doer HTTPDoer, logger *slog.Logger) (*Client, error) {
	if doer == nil {
		return nil, fmt.Errorf("http doer is required")
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid R2 base URL: %w", err)
	}
	if !u.IsAbs() || u.Scheme == "" {
		return nil, fmt.Errorf("R2 base URL must be absolute")
	}

	// Ensure the path ends with a slash so JoinPath behaves as expected.
	if !strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/"
	}

	return &Client{
		baseURL: u,
		token:   bearerToken,
		doer:    doer,
		logger:  logger,
	}, nil
}

// PutObject uploads data to R2 at the provided object key.
func (c *Client) PutObject(
	ctx context.Context,
	key string,
	payload []byte,
	options PutOptions,
) (PutResult, error) {
	if key == "" {
		return PutResult{}, fmt.Errorf("object key is required")
	}

	targetURL := c.baseURL.JoinPath(key)

	req, err := http.NewRequest(http.MethodPut, targetURL.String(), bytes.NewReader(payload))
	if err != nil {
		return PutResult{}, fmt.Errorf("failed to create request: %w", err)
	}

	req = req.WithContext(ctx)

	if options.ContentType != "" {
		req.Header.Set("Content-Type", options.ContentType)
	} else {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	// Published objects state their own cache policy; without this the CDN
	// applies heuristic caching to objects that mutate in place (ADR-0057).
	if options.CacheControl != "" {
		req.Header.Set("Cache-Control", options.CacheControl)
	}

	if options.IfMatch != "" {
		req.Header.Set("If-Match", options.IfMatch)
	}
	if options.IfNoneMatch != "" {
		req.Header.Set("If-None-Match", options.IfNoneMatch)
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.doer.Do(ctx, req)
	if err != nil {
		// No retries here; consider exponential backoff if transient errors become frequent.
		return PutResult{}, fmt.Errorf("put object request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drain a small portion of the body for debugging.
		const maxBody = int64(8 << 10) // 8KB
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		apiErr := &Error{
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
		if mappedErr := storageobjects.MapPutError(resp.StatusCode, options.FailIfExists, apiErr); mappedErr != nil {
			return PutResult{}, mappedErr
		}
		return PutResult{}, apiErr
	}

	return PutResult{
		ETag: resp.Header.Get("ETag"),
	}, nil
}

// ListObjects performs a Cloudflare R2 HTTP/JSON list request with the
// provided prefix. It decodes directly into the shared ListResult type.
func (c *Client) ListObjects(
	ctx context.Context,
	prefix string,
	continuationToken string,
	maxKeys int,
) (ListResult, error) {
	u := *c.baseURL
	values := url.Values{}
	if prefix != "" {
		values.Set("prefix", prefix)
	}
	if continuationToken != "" {
		values.Set("cursor", continuationToken)
	}
	if maxKeys > 0 {
		values.Set("limit", strconv.Itoa(maxKeys))
	}
	u.RawQuery = values.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return ListResult{}, fmt.Errorf("failed to build list request: %w", err)
	}
	req = req.WithContext(ctx)

	// Set headers for R2 native API
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-amz-content-sha256", emptyBodySHA256)

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.doer.Do(ctx, req)
	if err != nil {
		return ListResult{}, fmt.Errorf("list request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))

		c.logger.Info("R2ListObjects",
			"url_sha256", logredact.StringSHA256Hex(req.URL.String()),
			"status", resp.Status,
			"code", resp.StatusCode,
			"body_sha256", logredact.SHA256Hex(body),
		)

		apiErr := &Error{
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
		if mappedErr := storageobjects.MapListError(resp.StatusCode, apiErr); mappedErr != nil {
			return ListResult{}, mappedErr
		}
		return ListResult{}, apiErr
	}

	var page ListResult
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return ListResult{}, fmt.Errorf("failed to decode R2 list response: %w", err)
	}

	return page, nil
}

// GetObject retrieves an object payload optionally using range requests.
func (c *Client) GetObject(ctx context.Context, key string, opts GetOptions) (GetResult, error) {
	if key == "" {
		return GetResult{}, fmt.Errorf("object key is required")
	}

	targetURL := c.baseURL.JoinPath(key)
	req, err := http.NewRequest(http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return GetResult{}, fmt.Errorf("failed to create get request: %w", err)
	}
	req = req.WithContext(ctx)

	// Set headers for R2 native API
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-amz-content-sha256", emptyBodySHA256)

	// RangeLength == 0 with RangeStart == 0 (zero value) means full object.
	// RangeLength == 0 with RangeStart > 0 remains a 1-byte probe at that offset.
	switch {
	case opts.RangeLength > 0:
		end := opts.RangeStart + opts.RangeLength - 1
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", opts.RangeStart, end))
	case opts.RangeLength == 0 && opts.RangeStart > 0:
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", opts.RangeStart, opts.RangeStart))
	case opts.RangeLength < 0 && opts.RangeStart > 0:
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", opts.RangeStart))
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.doer.Do(ctx, req)
	if err != nil {
		return GetResult{}, fmt.Errorf("get object request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return GetResult{}, fmt.Errorf("failed to read object body: %w", err)
		}
		return GetResult{
			Data: data,
			ETag: resp.Header.Get("ETag"),
		}, nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		apiErr := &Error{
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
		if mappedErr := storageobjects.MapGetError(resp.StatusCode, apiErr); mappedErr != nil {
			return GetResult{}, mappedErr
		}
		return GetResult{}, apiErr
	}
}

// DeleteObject deletes an object at the given key. Missing objects are ignored.
func (c *Client) DeleteObject(ctx context.Context, key string) error {
	if key == "" {
		return fmt.Errorf("object key is required")
	}

	targetURL := c.baseURL.JoinPath(key)
	req, err := http.NewRequest(http.MethodDelete, targetURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create delete request: %w", err)
	}
	req = req.WithContext(ctx)

	// Set headers for R2 native API
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-amz-content-sha256", emptyBodySHA256)

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.doer.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("delete object request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		// NotFound is treated as success at the storage level.
		return nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		apiErr := &Error{
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
		if mappedErr := storageobjects.MapDeleteError(resp.StatusCode, apiErr); mappedErr != nil {
			return mappedErr
		}
		return apiErr
	}
}
