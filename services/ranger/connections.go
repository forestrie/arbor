package ranger

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// HTTPClient wraps http.Client with connection pooling
// This provides persistent connections for both queue operations and R2 reads
// Go's http.Transport is already thread-safe and handles connection pooling automatically
type HTTPClient struct {
	client    *http.Client
	transport *http.Transport
	logger    *slog.Logger
}

// NewHTTPClient creates a new HTTP client with persistent connections
// Optimized for periodic Cloudflare Queue polling and occasional R2 reads
func NewHTTPClient(logger *slog.Logger) *HTTPClient {
	// Configure transport for connection pooling
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			// Dial timeout: reasonable for Cloudflare services (typically <1s)
			// Allows retry attempts if DNS resolution is slow
			Timeout: 10 * time.Second,
			// KeepAlive: Set to 60s to exceed typical poll interval (default 5s)
			// This ensures connections stay alive between polls, avoiding reconnect overhead
			// Cloudflare services support keep-alive well
			KeepAlive: 60 * time.Second,
		}).DialContext,
		// MaxIdleConns: Total across all hosts (Queue API + R2)
		// We typically connect to 2 hosts max (queue + R2), so 100 is generous
		MaxIdleConns: 100,
		// MaxIdleConnsPerHost: Set to 2 for periodic polling use case
		// We make sequential requests (pull, then ack per message, occasional R2 read)
		// 2 connections per host allows some pipelining while keeping resource usage low
		MaxIdleConnsPerHost: 2,
		// IdleConnTimeout: Close idle connections after 90s of inactivity
		// Longer than poll interval (default 5s) ensures connection reuse
		// Prevents unnecessary reconnects while cleaning up truly idle connections
		IdleConnTimeout: 90 * time.Second,
		// DisableKeepAlives: false - critical for connection reuse
		// Enables HTTP keep-alive, allowing connection reuse across multiple requests
		DisableKeepAlives: false,
		// DisableCompression: false - enable gzip compression for API responses
		// Cloudflare APIs benefit from compression, reducing bandwidth
		DisableCompression: false,
		// TLSHandshakeTimeout: Timeout for TLS negotiation
		// Cloudflare uses TLS, this prevents hanging on slow TLS handshakes
		TLSHandshakeTimeout: 10 * time.Second,
		// ExpectContinueTimeout: Timeout for 100-continue header
		// Not typically used for GET/POST to Cloudflare APIs, but safe default
		ExpectContinueTimeout: 1 * time.Second,
		// ResponseHeaderTimeout: Timeout for receiving response headers
		// Cloudflare Queue pull operations typically complete quickly (<5s)
		// Set to 30s to handle network hiccups while avoiding long hangs
		ResponseHeaderTimeout: 30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		// Client Timeout: Total timeout for entire request (including body read)
		// Set to 30s to match ResponseHeaderTimeout
		// Handles slow response bodies or network issues
		Timeout: 30 * time.Second,
	}

	return &HTTPClient{
		client:    client,
		transport: transport,
		logger:    logger,
	}
}

// Do performs an HTTP request using the connection pool
// The underlying http.Transport is thread-safe and automatically:
// - Reuses existing connections when available
// - Creates new connections as needed (up to MaxIdleConnsPerHost)
// - Closes idle connections after IdleConnTimeout
//
// Connection lifecycle:
// - Connections are NOT explicitly closed here - caller must close resp.Body
// - When resp.Body.Close() is called, the connection is returned to the pool for reuse
// - The Transport automatically manages connection reuse based on HTTP keep-alive headers
// - No need to manually close connections or destroy the client instance
func (c *HTTPClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Perform the request - transport handles connection pooling automatically
	resp, err := c.client.Do(req.WithContext(ctx))

	if err != nil {
		// Connection error - close idle connections to force reconnection
		// This is safe to call concurrently (Transport is thread-safe)
		c.transport.CloseIdleConnections()
		c.logger.Warn("HTTP connection error - closed idle connections",
			"error", err,
		)
		return nil, err
	}

	// Note: resp.Body must be closed by caller - this returns the connection to the pool
	// if keep-alive is enabled, or closes it if Connection: close was received
	return resp, nil
}

// Close closes all idle connections and cleans up resources
// Safe to call multiple times (idempotent)
func (c *HTTPClient) Close() {
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	// Note: We don't nil out transport/client to allow reuse if needed
	// Transport.CloseIdleConnections() is idempotent
}

// GetClient returns the underlying http.Client for direct use if needed
func (c *HTTPClient) GetClient() *http.Client {
	return c.client
}
