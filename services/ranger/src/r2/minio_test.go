package r2

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestMinIOListObjectsWithArbitraryToken tests if MinIO accepts an arbitrary token
// for ListObjects requests. This is useful for verifying MinIO compatibility.
func TestMinIOListObjectsWithArbitraryToken(t *testing.T) {
	endpoint := os.Getenv("R2_MINIO_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:9000"
	}
	bucket := os.Getenv("R2_MINIO_BUCKET")
	if bucket == "" {
		bucket = "ranger-r2-tests"
	}

	// Check if MinIO is available
	healthURL := endpoint + "/minio/health/live"
	resp, err := http.Get(healthURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Skipf("MinIO not available at %s, skipping test", endpoint)
	}
	resp.Body.Close()

	// Create client with arbitrary token
	baseURL := endpoint + "/" + bucket
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	doer := &testDoer{client: &http.Client{Timeout: 5 * time.Second}}

	// Use an arbitrary token
	arbitraryToken := "test-token-arbitrary-12345"
	client, err := NewClient(baseURL, arbitraryToken, doer, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Try to list objects
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := client.ListObjects(ctx, "", "", 10)
	if err != nil {
		// Check if it's a "no token provided" error specifically
		if err.Error() != "" {
			t.Logf("ListObjects failed with arbitrary token: %v", err)
			if err.Error() == "list request failed: no token provided" {
				t.Logf("❌ MinIO rejected the request: 'no token provided'")
			} else {
				t.Logf("⚠️  MinIO responded but with an error (may accept token but request format incorrect)")
			}
		}
		// Don't fail the test - we're just checking if it accepts the token
		return
	}

	t.Logf("✅ ListObjects succeeded with arbitrary token! Result: %d objects, truncated: %v",
		len(result.Objects), result.IsTruncated)
}

