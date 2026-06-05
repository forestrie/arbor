package univocity

import (
	"strings"
	"testing"
)

func TestParseRPCURLs(t *testing.T) {
	t.Run("empty env", func(t *testing.T) {
		_, err := parseRPCURLs("")
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected required error, got %v", err)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		_, err := parseRPCURLs("{")
		if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
			t.Fatalf("expected JSON error, got %v", err)
		}
	})

	t.Run("empty object", func(t *testing.T) {
		_, err := parseRPCURLs("{}")
		if err == nil || !strings.Contains(err.Error(), "at least one chain") {
			t.Fatalf("expected empty map error, got %v", err)
		}
	})

	t.Run("bad chain key", func(t *testing.T) {
		_, err := parseRPCURLs(`{"foo":"https://rpc.example"}`)
		if err == nil || !strings.Contains(err.Error(), "invalid chainId") {
			t.Fatalf("expected chainId error, got %v", err)
		}
	})

	t.Run("empty url", func(t *testing.T) {
		_, err := parseRPCURLs(`{"84532":""}`)
		if err == nil || !strings.Contains(err.Error(), "empty rpc url") {
			t.Fatalf("expected empty url error, got %v", err)
		}
	})

	t.Run("valid", func(t *testing.T) {
		m, err := parseRPCURLs(`{"84532":"https://sepolia.base.org"}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m[84532] != "https://sepolia.base.org" {
			t.Fatalf("unexpected map: %v", m)
		}
	})
}
