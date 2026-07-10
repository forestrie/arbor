package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestNewClientValidURLAndToken(t *testing.T) {
	doer := &testDoer{client: http.DefaultClient}
	client, err := NewClient("https://example.com/bucket", "token-123", doer, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}

	if client.baseURL.Scheme != "https" {
		t.Fatalf("unexpected scheme %q", client.baseURL.Scheme)
	}
	if client.baseURL.Host != "example.com" {
		t.Fatalf("unexpected host %q", client.baseURL.Host)
	}
	if client.baseURL.Path != "/bucket/" {
		t.Fatalf("expected trailing slash in path, got %q", client.baseURL.Path)
	}
	if client.token != "token-123" {
		t.Fatalf("unexpected token %q", client.token)
	}
	if client.doer != doer {
		t.Fatalf("expected doer to be stored on client")
	}
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
		query   url.Values
		auth    string
		amzDate string
	}

	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>prefix/0000000000000001.log</Key>
    <LastModified>2024-01-02T03:04:05Z</LastModified>
    <ETag>"etag-1"</ETag>
    <Size>10</Size>
  </Contents>
  <Contents>
    <Key>prefix/0000000000000002.log</Key>
    <LastModified>2024-01-03T03:04:05Z</LastModified>
    <ETag>"etag-2"</ETag>
    <Size>20</Size>
  </Contents>
</ListBucketResult>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.query = r.URL.Query()
		received.auth = r.Header.Get("Authorization")
		received.amzDate = r.Header.Get("x-amz-date")
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, xmlBody)
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
	// Verify x-amz-date header is set when cloudflareCompat is enabled (default)
	if received.amzDate == "" {
		t.Fatalf("expected x-amz-date header to be set")
	}
	// Verify x-amz-date format (YYYYMMDDTHHMMSSZ)
	if len(received.amzDate) != 16 {
		t.Fatalf("unexpected x-amz-date format length: got %d, expected 16 (format: YYYYMMDDTHHMMSSZ)", len(received.amzDate))
	}
	if received.query.Get("list-type") != "2" {
		t.Fatalf("expected list-type=2, got %v", received.query)
	}
	if received.query.Get("prefix") != "prefix/" {
		t.Fatalf("unexpected prefix %s", received.query.Get("prefix"))
	}
	if received.query.Get("max-keys") != "500" {
		t.Fatalf("unexpected max-keys %s", received.query.Get("max-keys"))
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
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected status %d", apiErr.StatusCode)
	}
}

func TestClientListObjectsCloudflareCompatDisabled(t *testing.T) {
	var received struct {
		amzDate string
	}

	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IsTruncated>false</IsTruncated>
</ListBucketResult>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.amzDate = r.Header.Get("x-amz-date")
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, xmlBody)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger(), WithCloudflareCompat(false))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.ListObjects(context.Background(), "prefix/", "", 500)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}

	// Verify x-amz-date header is NOT set when cloudflareCompat is disabled
	if received.amzDate != "" {
		t.Fatalf("expected x-amz-date header to be empty when cloudflareCompat is disabled, got %q", received.amzDate)
	}
}

func TestClientGetObjectRange(t *testing.T) {
	var received struct {
		rangeHeader string
		auth        string
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.rangeHeader = r.Header.Get("Range")
		received.auth = r.Header.Get("Authorization")
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

func TestClientGetObjectFullWhenNegativeRangeLength(t *testing.T) {
	var received struct {
		rangeHeader string
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.rangeHeader = r.Header.Get("Range")
		w.Header().Set("ETag", `"etag-full"`)
		fmt.Fprint(w, "full-body")
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.GetObject(context.Background(), "path/object", GetOptions{
		RangeStart:  0,
		RangeLength: -1,
	})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}

	if received.rangeHeader != "" {
		t.Fatalf("expected no Range header, got %q", received.rangeHeader)
	}
	if string(result.Data) != "full-body" {
		t.Fatalf("unexpected body %q", result.Data)
	}
	if result.ETag != `"etag-full"` {
		t.Fatalf("unexpected etag %s", result.ETag)
	}
}

func TestClientGetObjectFullWhenZeroValueGetOptions(t *testing.T) {
	var received struct {
		rangeHeader string
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.rangeHeader = r.Header.Get("Range")
		w.Header().Set("ETag", `"etag-zero"`)
		fmt.Fprint(w, "full-via-zero")
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token", &testDoer{client: server.Client()}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// GetOptions{} must not send bytes=0-0 (1-byte truncate).
	result, err := client.GetObject(context.Background(), "path/object", GetOptions{})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}

	if received.rangeHeader != "" {
		t.Fatalf("expected no Range header for zero-value GetOptions, got %q", received.rangeHeader)
	}
	if string(result.Data) != "full-via-zero" {
		t.Fatalf("unexpected body %q", result.Data)
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

	// 404 Not Found should be mapped to ErrDoesNotExist
	if !errors.Is(err, massifstorage.ErrDoesNotExist) {
		t.Fatalf("expected ErrDoesNotExist, got %v", err)
	}
}
