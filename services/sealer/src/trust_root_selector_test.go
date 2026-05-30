package sealer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubTrustRootClient struct {
	key LogSigningKey
	err error
}

func (s *stubTrustRootClient) LogSigningKey(
	_ context.Context,
	_ string,
) (LogSigningKey, error) {
	return s.key, s.err
}

func TestSelectingTrustRootClient_PrimarySuccess(t *testing.T) {
	want := LogSigningKey{PublicKeyPEM: "primary-pem", Alg: "ES256"}
	fallback := &stubTrustRootClient{
		key: LogSigningKey{PublicKeyPEM: "fallback-pem"},
		err: nil,
	}
	sel := &SelectingTrustRootClient{
		Primary:  &stubTrustRootClient{key: want},
		Fallback: fallback,
	}
	got, err := sel.LogSigningKey(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKeyPEM != want.PublicKeyPEM {
		t.Fatalf("got %q want %q", got.PublicKeyPEM, want.PublicKeyPEM)
	}
}

func TestSelectingTrustRootClient_NotFoundUsesFallback(t *testing.T) {
	want := LogSigningKey{PublicKeyPEM: "fallback-pem", Alg: "ES256"}
	sel := &SelectingTrustRootClient{
		Primary: &stubTrustRootClient{
			err: ErrTrustRootNotFound,
		},
		Fallback: &stubTrustRootClient{key: want},
	}
	got, err := sel.LogSigningKey(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKeyPEM != want.PublicKeyPEM {
		t.Fatalf("got %q want %q", got.PublicKeyPEM, want.PublicKeyPEM)
	}
}

func TestSelectingTrustRootClient_PrimaryErrorNoFallback(t *testing.T) {
	sel := &SelectingTrustRootClient{
		Primary: &stubTrustRootClient{
			err: errors.New("upstream 500"),
		},
		Fallback: &stubTrustRootClient{
			key: LogSigningKey{PublicKeyPEM: "fallback-pem"},
		},
	}
	_, err := sel.LogSigningKey(context.Background(), "0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Fatal("expected primary error")
	}
	if errors.Is(err, ErrTrustRootNotFound) {
		t.Fatal("expected wrapped primary error, not not-found")
	}
}

func TestSelectingTrustRootClient_HTTPPrimary404UsesFallback(t *testing.T) {
	logID := "3123456789abcdef0123456789abcdef"
	want := LogSigningKey{PublicKeyPEM: "fallback-pem", Alg: "ES256"}

	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer primarySrv.Close()

	sel := &SelectingTrustRootClient{
		Primary: &HTTPTrustRootClient{
			BaseURL:    primarySrv.URL,
			HTTPClient: NewHTTPClient(nil),
		},
		Fallback: &stubTrustRootClient{key: want},
	}
	got, err := sel.LogSigningKey(context.Background(), logID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKeyPEM != want.PublicKeyPEM {
		t.Fatalf("got %q want %q", got.PublicKeyPEM, want.PublicKeyPEM)
	}
}
