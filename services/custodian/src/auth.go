package custodian

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AuthKind indicates the result of Bearer token validation.
type AuthKind int

const (
	AuthUnauthenticated AuthKind = iota
	AuthNormalApp
	AuthBootstrapApp
)

// AuthFromRequest returns the auth kind for the request using constant-time
// comparison. Expects Authorization: Bearer <token>.
func (a *API) AuthFromRequest(r *http.Request) AuthKind {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return AuthUnauthenticated
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return AuthUnauthenticated
	}
	token := strings.TrimSpace(auth[len(prefix):])
	if token == "" {
		return AuthUnauthenticated
	}
	if a.cfg.BootstrapAppToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.cfg.BootstrapAppToken)) == 1 {
		return AuthBootstrapApp
	}
	if a.cfg.AppToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.cfg.AppToken)) == 1 {
		return AuthNormalApp
	}
	return AuthUnauthenticated
}

// RequireNormalApp returns 401 if the request does not have a valid normal app token.
func (a *API) RequireNormalApp(w http.ResponseWriter, r *http.Request) bool {
	if a.AuthFromRequest(r) == AuthNormalApp {
		return true
	}
	a.writeProblem(w, r, http.StatusUnauthorized, "about:blank", "unauthorized", "valid app token required")
	return false
}

// RequireBootstrapApp returns 401 if the request does not have a valid bootstrap app token.
func (a *API) RequireBootstrapApp(w http.ResponseWriter, r *http.Request) bool {
	if a.AuthFromRequest(r) == AuthBootstrapApp {
		return true
	}
	a.writeProblem(w, r, http.StatusUnauthorized, "about:blank", "unauthorized", "bootstrap app token required")
	return false
}
