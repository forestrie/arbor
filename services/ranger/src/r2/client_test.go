package r2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

type testDoer struct {
	client *http.Client
}

func (t *testDoer) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return t.client.Do(req.WithContext(ctx))
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

func TestClientPutObject(t *testing.T) {
	var received struct {
		method      string
		path        string
		auth        string
		ifNoneMatch string
		contentType string
		body        []byte
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		received.method = r.Method
		received.path = r.URL.Path
		received.auth = r.Header.Get("Authorization")
		received.ifNoneMatch = r.Header.Get("If-None-Match")
		received.contentType = r.Header.Get("Content-Type")
		received.body = body
		w.Header().Set("ETag", `"etag-value"`)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client, err := NewClient(
		server.URL+"/bucket",
		"token-123",
		&testDoer{client: server.Client()},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.PutObject(
		context.Background(),
		"v1/mmrs/tenant/foo",
		[]byte("payload"),
		PutOptions{
			ContentType: "application/custom",
			IfNoneMatch: "*",
		},
	)
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	if result.ETag != `"etag-value"` {
		t.Fatalf("expected etag, got %q", result.ETag)
	}

	if received.method != http.MethodPut {
		t.Fatalf("expected PUT, got %s", received.method)
	}
	if received.path != "/bucket/v1/mmrs/tenant/foo" {
		t.Fatalf("unexpected path %s", received.path)
	}
	if received.auth != "Bearer token-123" {
		t.Fatalf("unexpected auth header %s", received.auth)
	}
	if received.ifNoneMatch != "*" {
		t.Fatalf("expected If-None-Match *, got %q", received.ifNoneMatch)
	}
	if received.contentType != "application/custom" {
		t.Fatalf("unexpected content type %s", received.contentType)
	}
	if string(received.body) != "payload" {
		t.Fatalf("unexpected body %q", string(received.body))
	}
}

func TestClientPutObjectError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	client, err := NewClient(
		server.URL,
		"token-123",
		&testDoer{client: server.Client()},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.PutObject(context.Background(), "object", []byte("payload"), PutOptions{})
	if err == nil {
		t.Fatal("expected error")
	}

	// 403 Forbidden should be mapped to ErrNotAvailable
	if !errors.Is(err, massifstorage.ErrNotAvailable) {
		t.Fatalf("expected ErrNotAvailable, got %v", err)
	}
}

func TestClientListObjects(t *testing.T) {
	var received struct {
		prefix              string
		cursor              string
		limit               string
		auth                string
		accept              string
		xAmzContentSha256  string
	}

	page := ListResult{
		Objects: []ObjectSummary{
			{Key: "prefix/0000000000000001.log", LastModified: "2024-01-02T03:04:05Z", ETag: "\"etag-1\"", Size: 10},
			{Key: "prefix/0000000000000002.log", LastModified: "2024-01-03T03:04:05Z", ETag: "\"etag-2\"", Size: 20},
		},
		NextContinuationToken: "",
		IsTruncated:           false,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		received.prefix = q.Get("prefix")
		received.cursor = q.Get("cursor")
		received.limit = q.Get("limit")
		received.auth = r.Header.Get("Authorization")
		received.accept = r.Header.Get("Accept")
		received.xAmzContentSha256 = r.Header.Get("x-amz-content-sha256")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.ListObjects(context.Background(), "prefix/", "", 500)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}

	if received.auth != "Bearer token" {
		t.Fatalf("unexpected auth %s", received.auth)
	}
	if received.accept != "application/json" {
		t.Fatalf("expected Accept: application/json, got %q", received.accept)
	}
	if received.xAmzContentSha256 != emptyBodySHA256 {
		t.Fatalf("expected x-amz-content-sha256 %q, got %q", emptyBodySHA256, received.xAmzContentSha256)
	}
	if received.prefix != "prefix/" {
		t.Fatalf("unexpected prefix %s", received.prefix)
	}
	if received.limit != "500" {
		t.Fatalf("unexpected limit %s", received.limit)
	}
	if received.cursor != "" {
		t.Fatalf("expected empty cursor, got %s", received.cursor)
	}

	if result.IsTruncated {
		t.Fatalf("expected not truncated")
	}
	if len(result.Objects) != 2 {
		t.Fatalf("expected 2 objects, got %d (result=%+v)", len(result.Objects), result)
	}

	if result.Objects[1].Key != "prefix/0000000000000002.log" {
		t.Fatalf("unexpected key %s", result.Objects[1].Key)
	}
	if result.Objects[1].ETag != `"etag-2"` {
		t.Fatalf("unexpected etag %s", result.Objects[1].ETag)
	}
	if result.Objects[1].Size != 20 {
		t.Fatalf("unexpected size %d", result.Objects[1].Size)
	}
	expectedTime := "2024-01-03T03:04:05Z"
	if result.Objects[1].LastModified != expectedTime {
		t.Fatalf("unexpected last modified %s", result.Objects[1].LastModified)
	}
}

func TestClientListObjectsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.ListObjects(context.Background(), "prefix/", "token", 10)
	if err == nil {
		t.Fatal("expected error")
	}

	// 400 Bad Request is not mapped, so we should get the raw *Error
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, apiErr.StatusCode)
	}
	if apiErr.Body == "" {
		t.Fatal("expected body to be captured")
	}
}

func TestClientGetObjectRange(t *testing.T) {
	var received struct {
		rangeHeader        string
		auth               string
		accept             string
		xAmzContentSha256  string
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.rangeHeader = r.Header.Get("Range")
		received.auth = r.Header.Get("Authorization")
		received.accept = r.Header.Get("Accept")
		received.xAmzContentSha256 = r.Header.Get("x-amz-content-sha256")
		w.Header().Set("ETag", `"etag"`)
		w.WriteHeader(http.StatusPartialContent)
		fmt.Fprint(w, "hello")
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.GetObject(context.Background(), "path/object", GetOptions{
		RangeStart:  0,
		RangeLength: 5,
	})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}

	if received.auth != "Bearer token" {
		t.Fatalf("unexpected auth %s", received.auth)
	}
	if received.accept != "application/json" {
		t.Fatalf("expected Accept: application/json, got %q", received.accept)
	}
	if received.xAmzContentSha256 != emptyBodySHA256 {
		t.Fatalf("expected x-amz-content-sha256 %q, got %q", emptyBodySHA256, received.xAmzContentSha256)
	}
	if received.rangeHeader != "bytes=0-4" {
		t.Fatalf("unexpected range %s", received.rangeHeader)
	}

	if string(result.Data) != "hello" {
		t.Fatalf("unexpected body %q", result.Data)
	}
	if result.ETag != `"etag"` {
		t.Fatalf("unexpected etag %s", result.ETag)
	}
}

func TestClientGetObjectError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.GetObject(context.Background(), "missing", GetOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, massifstorage.ErrDoesNotExist) {
		t.Fatalf("expected ErrDoesNotExist, got %v", err)
	}
}

// NewClient Validation Tests

func TestNewClientNilDoer(t *testing.T) {
	_, err := NewClient("https://example.com", "token", nil, newTestLogger())
	if err == nil {
		t.Fatal("expected error for nil doer")
	}
	if !strings.Contains(err.Error(), "http doer is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewClientInvalidURL(t *testing.T) {
	_, err := NewClient("://invalid", "token", &testDoer{client: &http.Client{}}, newTestLogger())
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	if !strings.Contains(err.Error(), "invalid R2 base URL") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewClientRelativeURL(t *testing.T) {
	_, err := NewClient("relative/path", "token", &testDoer{client: &http.Client{}}, newTestLogger())
	if err == nil {
		t.Fatal("expected error for relative URL")
	}
	if !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewClientValidURL(t *testing.T) {
	client, err := NewClient("https://example.com/bucket/", "token", &testDoer{client: &http.Client{}}, newTestLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected client to be created")
	}
}

// PutObject Additional Tests

func TestClientPutObjectWithIfMatch(t *testing.T) {
	var received struct {
		ifMatch string
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.ifMatch = r.Header.Get("If-Match")
		w.Header().Set("ETag", `"etag-value"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(
		server.URL,
		"token",
		&testDoer{client: server.Client()},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.PutObject(
		context.Background(),
		"object",
		[]byte("payload"),
		PutOptions{
			IfMatch: `"existing-etag"`,
		},
	)
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	if received.ifMatch != `"existing-etag"` {
		t.Fatalf("expected If-Match header %q, got %q", `"existing-etag"`, received.ifMatch)
	}
}

func TestClientPutObjectEmptyKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(
		server.URL,
		"token",
		&testDoer{client: server.Client()},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.PutObject(context.Background(), "", []byte("payload"), PutOptions{})
	if err == nil {
		t.Fatal("expected error for empty key")
	}
	if !strings.Contains(err.Error(), "object key is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientPutObjectDefaultContentType(t *testing.T) {
	var received struct {
		contentType string
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.contentType = r.Header.Get("Content-Type")
		w.Header().Set("ETag", `"etag"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(
		server.URL,
		"token",
		&testDoer{client: server.Client()},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.PutObject(context.Background(), "object", []byte("payload"), PutOptions{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	if received.contentType != "application/octet-stream" {
		t.Fatalf("expected default content type application/octet-stream, got %q", received.contentType)
	}
}

func TestClientPutObjectStatusOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"etag-value"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(
		server.URL,
		"token",
		&testDoer{client: server.Client()},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.PutObject(context.Background(), "object", []byte("payload"), PutOptions{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	if result.ETag != `"etag-value"` {
		t.Fatalf("expected etag, got %q", result.ETag)
	}
}

// GetObject Additional Tests

func TestClientGetObjectFull(t *testing.T) {
	var received struct {
		rangeHeader string
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.rangeHeader = r.Header.Get("Range")
		w.Header().Set("ETag", `"etag"`)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "full content")
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Use negative RangeLength to indicate no range (full object)
	result, err := client.GetObject(context.Background(), "object", GetOptions{
		RangeLength: -1,
	})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}

	// When RangeLength is negative and RangeStart is 0, no Range header should be set
	if received.rangeHeader != "" {
		t.Fatalf("expected no Range header for full object, got %q", received.rangeHeader)
	}
	if string(result.Data) != "full content" {
		t.Fatalf("unexpected body %q", result.Data)
	}
	if result.ETag != `"etag"` {
		t.Fatalf("unexpected etag %s", result.ETag)
	}
}

func TestClientGetObjectOpenEndedRange(t *testing.T) {
	var received struct {
		rangeHeader string
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.rangeHeader = r.Header.Get("Range")
		w.Header().Set("ETag", `"etag"`)
		w.WriteHeader(http.StatusPartialContent)
		fmt.Fprint(w, "content from offset")
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.GetObject(context.Background(), "object", GetOptions{
		RangeStart:  10,
		RangeLength: -1,
	})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}

	if received.rangeHeader != "bytes=10-" {
		t.Fatalf("unexpected range header %q", received.rangeHeader)
	}
	if string(result.Data) != "content from offset" {
		t.Fatalf("unexpected body %q", result.Data)
	}
}

func TestClientGetObjectZeroLengthRange(t *testing.T) {
	var received struct {
		rangeHeader string
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.rangeHeader = r.Header.Get("Range")
		w.Header().Set("ETag", `"etag"`)
		w.WriteHeader(http.StatusPartialContent)
		// Zero-length range should return empty body
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.GetObject(context.Background(), "object", GetOptions{
		RangeStart:  5,
		RangeLength: 0,
	})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}

	if received.rangeHeader != "bytes=5-5" {
		t.Fatalf("unexpected range header %q", received.rangeHeader)
	}
	if len(result.Data) != 0 {
		t.Fatalf("expected empty body for zero-length range, got %d bytes", len(result.Data))
	}
}

func TestClientGetObjectEmptyKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.GetObject(context.Background(), "", GetOptions{})
	if err == nil {
		t.Fatal("expected error for empty key")
	}
	if !strings.Contains(err.Error(), "object key is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ListObjects Additional Tests

func TestClientListObjectsWithContinuationToken(t *testing.T) {
	var received struct {
		cursor string
	}

	page := ListResult{
		Objects: []ObjectSummary{
			{Key: "prefix/obj3.log", LastModified: "2024-01-04T03:04:05Z", ETag: "\"etag-3\"", Size: 30},
		},
		NextContinuationToken: "",
		IsTruncated:           false,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		received.cursor = q.Get("cursor")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.ListObjects(context.Background(), "prefix/", "cursor-token-123", 100)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}

	if received.cursor != "cursor-token-123" {
		t.Fatalf("expected cursor %q, got %q", "cursor-token-123", received.cursor)
	}
	if len(result.Objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(result.Objects))
	}
}

func TestClientListObjectsTruncated(t *testing.T) {
	page := ListResult{
		Objects: []ObjectSummary{
			{Key: "prefix/obj1.log", LastModified: "2024-01-02T03:04:05Z", ETag: "\"etag-1\"", Size: 10},
		},
		NextContinuationToken: "next-token-456",
		IsTruncated:           true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.ListObjects(context.Background(), "prefix/", "", 1)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}

	if !result.IsTruncated {
		t.Fatal("expected truncated result")
	}
	if result.NextContinuationToken != "next-token-456" {
		t.Fatalf("expected continuation token %q, got %q", "next-token-456", result.NextContinuationToken)
	}
}

func TestClientListObjectsEmptyPrefix(t *testing.T) {
	var received struct {
		prefix string
	}

	page := ListResult{
		Objects: []ObjectSummary{},
		NextContinuationToken: "",
		IsTruncated:           false,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		received.prefix = q.Get("prefix")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.ListObjects(context.Background(), "", "", 100)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}

	if received.prefix != "" {
		t.Fatalf("expected empty prefix, got %q", received.prefix)
	}
	if len(result.Objects) != 0 {
		t.Fatalf("expected 0 objects, got %d", len(result.Objects))
	}
}

func TestClientListObjectsZeroMaxKeys(t *testing.T) {
	var received struct {
		limit string
	}

	page := ListResult{
		Objects: []ObjectSummary{},
		NextContinuationToken: "",
		IsTruncated:           false,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		received.limit = q.Get("limit")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.ListObjects(context.Background(), "prefix/", "", 0)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}

	// Zero maxKeys should not include limit parameter
	if received.limit != "" {
		t.Fatalf("expected empty limit for zero maxKeys, got %q", received.limit)
	}
	if len(result.Objects) != 0 {
		t.Fatalf("expected 0 objects, got %d", len(result.Objects))
	}
}

// DeleteObject Tests

func TestClientDeleteObjectSuccess(t *testing.T) {
	var received struct {
		method             string
		path               string
		auth               string
		accept             string
		xAmzContentSha256  string
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.method = r.Method
		received.path = r.URL.Path
		received.auth = r.Header.Get("Authorization")
		received.accept = r.Header.Get("Accept")
		received.xAmzContentSha256 = r.Header.Get("x-amz-content-sha256")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(
		server.URL+"/bucket",
		"token-123",
		&testDoer{client: server.Client()},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	err = client.DeleteObject(context.Background(), "object/key")
	if err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}

	if received.method != http.MethodDelete {
		t.Fatalf("expected DELETE, got %s", received.method)
	}
	if received.path != "/bucket/object/key" {
		t.Fatalf("unexpected path %s", received.path)
	}
	if received.auth != "Bearer token-123" {
		t.Fatalf("unexpected auth header %s", received.auth)
	}
	if received.accept != "application/json" {
		t.Fatalf("expected Accept: application/json, got %q", received.accept)
	}
	if received.xAmzContentSha256 != emptyBodySHA256 {
		t.Fatalf("expected x-amz-content-sha256 %q, got %q", emptyBodySHA256, received.xAmzContentSha256)
	}
}

func TestClientDeleteObjectStatusOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(
		server.URL,
		"token",
		&testDoer{client: server.Client()},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	err = client.DeleteObject(context.Background(), "object")
	if err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
}

func TestClientDeleteObjectNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewClient(
		server.URL,
		"token",
		&testDoer{client: server.Client()},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// NotFound should be treated as success
	err = client.DeleteObject(context.Background(), "missing")
	if err != nil {
		t.Fatalf("DeleteObject should succeed for missing object, got: %v", err)
	}
}

func TestClientDeleteObjectError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	client, err := NewClient(
		server.URL,
		"token",
		&testDoer{client: server.Client()},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	err = client.DeleteObject(context.Background(), "object")
	if err == nil {
		t.Fatal("expected error")
	}

	// 403 Forbidden should be mapped to ErrNotAvailable
	if !errors.Is(err, massifstorage.ErrNotAvailable) {
		t.Fatalf("expected ErrNotAvailable, got %v", err)
	}
}

func TestClientDeleteObjectEmptyKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(
		server.URL,
		"token",
		&testDoer{client: server.Client()},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	err = client.DeleteObject(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty key")
	}
	if !strings.Contains(err.Error(), "object key is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}
