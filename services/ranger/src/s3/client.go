package s3

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	storageobjects "github.com/forestrie/arbor/services/ranger/storageobjects"
)

// HTTPDoer abstracts the subset of http.Client used by the S3 client.
// ranger.HTTPClient satisfies this interface.
type HTTPDoer interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// Client provides minimal helpers for interacting with an S3-compatible
// endpoint using the REST API. Connection pooling is managed by the provided
// HTTPDoer implementation.
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

// Error represents an HTTP error returned by the S3-compatible API.
type Error struct {
	StatusCode int
	Body       string
}

func (e *Error) Error() string {
	return fmt.Sprintf("s3 api error: status=%d body=%q", e.StatusCode, e.Body)
}

// NewClient constructs a Client using the provided baseURL and bearer token.
func NewClient(baseURL, bearerToken string, doer HTTPDoer, logger *slog.Logger) (*Client, error) {
	if doer == nil {
		return nil, fmt.Errorf("http doer is required")
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid S3 base URL: %w", err)
	}
	if !u.IsAbs() || u.Scheme == "" {
		return nil, fmt.Errorf("S3 base URL must be absolute")
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

// PutObject uploads data at the provided object key.
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
		return PutResult{}, fmt.Errorf("put object request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
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

// ListObjects performs an S3 ListObjectsV2 request with the provided prefix.
func (c *Client) ListObjects(
	ctx context.Context,
	prefix string,
	continuationToken string,
	maxKeys int,
) (ListResult, error) {
	u := *c.baseURL
	values := url.Values{}
	values.Set("list-type", "2")
	if prefix != "" {
		values.Set("prefix", prefix)
	}
	if continuationToken != "" {
		values.Set("continuation-token", continuationToken)
	}
	if maxKeys > 0 {
		values.Set("max-keys", strconv.Itoa(maxKeys))
	}
	u.RawQuery = values.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return ListResult{}, fmt.Errorf("failed to build list request: %w", err)
	}
	req = req.WithContext(ctx)
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

		c.logger.Info("ListObject", "scheme", req.URL.Scheme, "host", req.URL.Scheme, "path", req.URL.Path)
		c.logger.Info("ListObject", "raw_query", req.URL.RawQuery)
		c.logger.Info("ListObjects", "status", resp.Status, "code", resp.StatusCode)
		c.logger.Info("ListObjects", "body", body)

		apiErr := &Error{
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
		if mappedErr := storageobjects.MapListError(resp.StatusCode, apiErr); mappedErr != nil {
			return ListResult{}, mappedErr
		}
		return ListResult{}, apiErr
	}

	dec := xml.NewDecoder(resp.Body)
	dec.Strict = false

	result := ListResult{}

	type rawObject struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
	}

	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ListResult{}, fmt.Errorf("failed to parse list response: %w", err)
		}

		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}

		switch start.Name.Local {
		case "IsTruncated":
			var truncated string
			if err := dec.DecodeElement(&truncated, &start); err != nil {
				return ListResult{}, fmt.Errorf("failed to decode truncation flag: %w", err)
			}
			result.IsTruncated = strings.EqualFold(strings.TrimSpace(truncated), "true")
		case "NextContinuationToken":
			var token string
			if err := dec.DecodeElement(&token, &start); err != nil {
				return ListResult{}, fmt.Errorf("failed to decode continuation token: %w", err)
			}
			result.NextContinuationToken = strings.TrimSpace(token)
		case "Contents":
			var raw rawObject
			if err := dec.DecodeElement(&raw, &start); err != nil {
				return ListResult{}, fmt.Errorf("failed to decode object summary: %w", err)
			}
			result.Objects = append(result.Objects, ObjectSummary{
				Key:          strings.TrimSpace(raw.Key),
				LastModified: strings.TrimSpace(raw.LastModified),
				ETag:         strings.TrimSpace(raw.ETag),
				Size:         raw.Size,
			})
		}
	}

	return result, nil
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

	if opts.RangeLength >= 0 {
		end := opts.RangeStart + opts.RangeLength - 1
		if opts.RangeLength == 0 {
			end = opts.RangeStart
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", opts.RangeStart, end))
	} else if opts.RangeStart > 0 {
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
