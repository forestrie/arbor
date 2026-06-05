package univocity

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
)

// bearerToken extracts a bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[len("bearer "):])
	}
	return h
}

// requireToken enforces the configured API token on write/authorize endpoints.
func (a API) requireToken(w http.ResponseWriter, r *http.Request) bool {
	if a.APIToken == "" {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
			"endpoint disabled", "UNIVOCITY_API_TOKEN not configured")
		return false
	}
	got := bearerToken(r)
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(a.APIToken)) != 1 {
		a.writeProblem(w, r, http.StatusUnauthorized, "about:blank",
			"unauthorized", "missing or invalid bearer token")
		return false
	}
	return true
}

// requireAdminToken enforces the admin token on destructive endpoints.
func (a API) requireAdminToken(w http.ResponseWriter, r *http.Request) bool {
	if a.AdminToken == "" {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
			"endpoint disabled", "UNIVOCITY_ADMIN_TOKEN not configured")
		return false
	}
	got := bearerToken(r)
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(a.AdminToken)) != 1 {
		a.writeProblem(w, r, http.StatusUnauthorized, "about:blank",
			"unauthorized", "missing or invalid admin bearer token")
		return false
	}
	return true
}

// bootstrapCache memoizes per-(chainId,contract) on-chain bootstrap keys.
type bootstrapCache struct {
	mu   sync.Mutex
	keys map[string][]byte
}

// NewBootstrapCache constructs an empty per-forest bootstrap key cache.
func NewBootstrapCache() *bootstrapCache {
	return &bootstrapCache{keys: make(map[string][]byte)}
}

func (c *bootstrapCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.keys[key]
	return v, ok
}

func (c *bootstrapCache) put(key string, val []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys[key] = val
}
