package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPTrustRootClient_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &HTTPTrustRootClient{
		BaseURL:    srv.URL,
		HTTPClient: NewHTTPClient(nil),
	}
	_, err := client.LogSigningKey(
		context.Background(),
		"0123456789abcdef0123456789abcdef",
	)
	if !errors.Is(err, ErrTrustRootNotFound) {
		t.Fatalf("expected ErrTrustRootNotFound, got %v", err)
	}
}

func TestHTTPTrustRootClient_SendsBearerToken(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := "4123456789abcdef0123456789abcdef"
	const wantToken = "coord-test-token"

	inner := newBYOKTrustRootServer(t, logID, &rootPriv.PublicKey, nil)
	defer inner.Close()

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if gotAuth != "Bearer "+wantToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		innerURL := inner.URL + r.URL.Path
		proxyReq, err := http.NewRequestWithContext(
			r.Context(), r.Method, innerURL, nil,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		proxyReq.Header.Set("Accept", "application/cbor")
		proxyResp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer proxyResp.Body.Close()
		for k, vv := range proxyResp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(proxyResp.StatusCode)
		_, _ = io.Copy(w, proxyResp.Body)
	}))
	defer srv.Close()

	client := &HTTPTrustRootClient{
		BaseURL:    srv.URL,
		Token:      wantToken,
		HTTPClient: NewHTTPClient(nil),
	}
	if _, err := client.LogSigningKey(context.Background(), logID); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer "+wantToken {
		t.Fatalf("Authorization=%q want Bearer %q", gotAuth, wantToken)
	}
}

func TestHTTPTrustRootClient_ServerErrorNoNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := &HTTPTrustRootClient{
		BaseURL:    srv.URL,
		HTTPClient: NewHTTPClient(nil),
	}
	_, err := client.LogSigningKey(
		context.Background(),
		"0123456789abcdef0123456789abcdef",
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrTrustRootNotFound) {
		t.Fatal("500 must not map to ErrTrustRootNotFound")
	}
}
