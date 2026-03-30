package custodian

import (
	"os"
	"testing"
)

func TestLoadConfig_LogIDCacheSize(t *testing.T) {
	if err := os.Unsetenv("LOG_ID_CACHE_SIZE"); err != nil {
		t.Fatal(err)
	}
	cfg := LoadConfig()
	if cfg.LogIDCacheSize != defaultLogIDCacheSize {
		t.Fatalf("unset env: got %d want %d", cfg.LogIDCacheSize, defaultLogIDCacheSize)
	}

	t.Setenv("LOG_ID_CACHE_SIZE", "0")
	if cfg0 := LoadConfig(); cfg0.LogIDCacheSize != 0 {
		t.Fatalf("explicit 0: got %d", cfg0.LogIDCacheSize)
	}

	t.Setenv("LOG_ID_CACHE_SIZE", "42")
	if cfg42 := LoadConfig(); cfg42.LogIDCacheSize != 42 {
		t.Fatalf("explicit 42: got %d", cfg42.LogIDCacheSize)
	}

	t.Setenv("LOG_ID_CACHE_SIZE", "nope")
	if cfgBad := LoadConfig(); cfgBad.LogIDCacheSize != defaultLogIDCacheSize {
		t.Fatalf("invalid LOG_ID_CACHE_SIZE should keep default, got %d", cfgBad.LogIDCacheSize)
	}
}
