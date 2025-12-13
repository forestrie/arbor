package sealer

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// HTTPClient wraps http.Client with connection pooling.
// Optimized for periodic Cloudflare Queue polling.
type HTTPClient struct {
	client    *http.Client
	transport *http.Transport
	logger    *slog.Logger
}

// NewHTTPClient creates a new HTTP client with persistent connections.
func NewHTTPClient(logger *slog.Logger) *HTTPClient {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &HTTPClient{
		client:    client,
		transport: transport,
		logger:    logger,
	}
}

// Do performs an HTTP request using the connection pool.
func (c *HTTPClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	resp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		c.transport.CloseIdleConnections()
		c.logger.Warn("HTTP connection error - closed idle connections", "error", err)
		return nil, err
	}
	return resp, nil
}

// Close closes all idle connections and cleans up resources.
func (c *HTTPClient) Close() {
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

// GetClient returns the underlying http.Client for direct use if needed.
func (c *HTTPClient) GetClient() *http.Client {
	return c.client
}
