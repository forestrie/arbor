package publishproof

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// PublicBucketGetter reads grant-store objects over anonymous HTTPS from a
// bucket's public domain (the Cloudflare managed domain the forest-1
// provisioning enables on the grants bucket). It is the pure-public-data path
// of ADR-0047: no credentials, so any third party can run the same
// resolution.
type PublicBucketGetter struct {
	baseURL string
	client  *http.Client
}

// NewPublicBucketGetter builds a getter over the bucket's public base URL.
// client may be nil, in which case http.DefaultClient is used.
func NewPublicBucketGetter(baseURL string, client *http.Client) *PublicBucketGetter {
	if client == nil {
		client = http.DefaultClient
	}
	return &PublicBucketGetter{baseURL: strings.TrimSuffix(baseURL, "/"), client: client}
}

// Get fetches one object by key. Missing objects return an error matching
// massifstorage.ErrDoesNotExist (the ObjectGetter contract).
func (g *PublicBucketGetter) Get(ctx context.Context, key string) ([]byte, error) {
	endpoint := g.baseURL + "/" + (&url.URL{Path: key}).EscapedPath()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", key, err)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", key, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResolveObjectBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", key, err)
		}
		return body, nil
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s: %w", key, massifstorage.ErrDoesNotExist)
	default:
		return nil, fmt.Errorf("get %s: HTTP %d", key, resp.StatusCode)
	}
}
