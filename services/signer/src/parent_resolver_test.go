package signer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/logid"
)

// fetchRootLogID status classification (plan-2607-10 slice 04): 404 and other
// non-200s return logid.Zero without panicking; 200 parses the root. The warn
// logging is exercised implicitly (loud, never silent — see parent_resolver.go).
func TestFetchRootLogID_StatusClassification(t *testing.T) {
	parent := logid.UUID{15: 7}
	var root logid.UUID
	root[0] = 1

	cases := []struct {
		name   string
		status int
		body   string
		want   logid.UUID
	}{
		{"ok", http.StatusOK, `{"exists":true,"rootLogId":"` + root.String() + `"}`, root},
		{"not found is zero", http.StatusNotFound, `{"title":"log not resolved"}`, logid.Zero},
		{"unavailable is zero", http.StatusServiceUnavailable, ``, logid.Zero},
		{"bad gateway is zero", http.StatusBadGateway, ``, logid.Zero},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			p := &ParentResolver{UnivocityURL: srv.URL, HTTPClient: srv.Client()}
			got := p.fetchRootLogID(context.Background(), parent)
			if got != tc.want {
				t.Fatalf("%s: got %s want %s", tc.name, got.String(), tc.want.String())
			}
		})
	}
}
