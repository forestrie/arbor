package univocity

import (
	"strings"
	"testing"
	"time"
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

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("UNIVOCITY_RPC_URLS", `{"84532":"http://localhost:8545"}`)
	t.Setenv("GENESIS_R2_URL", "https://r2.example")
	t.Setenv("R2_URL", "https://logs.r2.example")
	t.Setenv("AWS_ACCESS_KEY_ID", "akid")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
}

func TestLoadConfig_ReservationTTL(t *testing.T) {
	setRequiredEnv(t)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ReservationTTL != DefaultReservationTTL {
		t.Fatalf("default TTL %v, want %v", cfg.ReservationTTL, DefaultReservationTTL)
	}

	t.Setenv("UNIVOCITY_RESERVATION_TTL", "36h")
	if cfg, err = LoadConfig(); err != nil || cfg.ReservationTTL != 36*time.Hour {
		t.Fatalf("TTL %v err %v, want 36h", cfg.ReservationTTL, err)
	}

	t.Setenv("UNIVOCITY_RESERVATION_TTL", "0s")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("a zero TTL must be refused")
	}
}
