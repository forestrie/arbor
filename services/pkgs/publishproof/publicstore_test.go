package publishproof

import (
	"net/http"
	"net/http/httptest"
	"testing"

	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/stretchr/testify/require"
)

// The public bucket getter serves the resolver from a Cloudflare-managed
// public domain (anonymous HTTPS GET): 200 -> bytes, 404 -> the store
// not-found sentinel, anything else -> a hard error.
func TestPublicBucketGetter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/forests/index/forest/20000000-0000-4000-8000-000000000002":
			_, _ = w.Write([]byte("10000000-0000-4000-8000-000000000001"))
		case "/rate-limited":
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	store := NewPublicBucketGetter(srv.URL+"/", srv.Client())

	body, err := store.Get(t.Context(), "forests/index/forest/20000000-0000-4000-8000-000000000002")
	require.NoError(t, err)
	require.Equal(t, "10000000-0000-4000-8000-000000000001", string(body))

	_, err = store.Get(t.Context(), "forests/forest/absent/genesis.cbor")
	require.ErrorIs(t, err, massifstorage.ErrDoesNotExist)

	_, err = store.Get(t.Context(), "rate-limited")
	require.Error(t, err)
	require.NotErrorIs(t, err, massifstorage.ErrDoesNotExist)
	require.Contains(t, err.Error(), "429")
}
