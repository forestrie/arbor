package custodian

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/logredact"
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

// TestLoadConfig_DelegateKeyVoucherTTL: DELEGATE_KEY_VOUCHER_TTL defaults to
// 24h; a value outside 1h..720h (30 days) or unparseable falls back to the
// default and is reported as an error at boot, never an exit (slice 07).
func TestLoadConfig_DelegateKeyVoucherTTL(t *testing.T) {
	cases := []struct {
		raw     string
		want    time.Duration
		invalid bool
	}{
		{"", 24 * time.Hour, false},
		{"6h", 6 * time.Hour, false},
		{"1h", time.Hour, false},
		{"720h", 720 * time.Hour, false},
		{"30m", 24 * time.Hour, true},
		{"960h", 24 * time.Hour, true},
		{"soon", 24 * time.Hour, true},
	}
	for _, c := range cases {
		t.Setenv("DELEGATE_KEY_VOUCHER_TTL", c.raw)
		cfg := LoadConfig()
		if cfg.DelegateKeyVoucherTTL != c.want {
			t.Fatalf("%q: TTL = %s, want %s", c.raw, cfg.DelegateKeyVoucherTTL, c.want)
		}

		var logs bytes.Buffer
		cfg.LogConfig(slog.New(slog.NewJSONHandler(&logs, nil)))
		out := logs.String()
		if !strings.Contains(out, `"name":"DELEGATE_KEY_VOUCHER_TTL","value":"`+c.want.String()+`"`) {
			t.Fatalf("%q: effective TTL not logged at boot:\n%s", c.raw, out)
		}
		gotErr := strings.Contains(out, `"level":"ERROR","msg":"DELEGATE_KEY_VOUCHER_TTL invalid; using the default"`)
		if gotErr != c.invalid {
			t.Fatalf("%q: error logged = %v, want %v:\n%s", c.raw, gotErr, c.invalid, out)
		}
		if c.invalid && !strings.Contains(out, `"input":"`+c.raw+`"`) {
			t.Fatalf("%q: error line must name the rejected input:\n%s", c.raw, out)
		}
	}
}

// TestLogConfig_SecretsAsFingerprints: the boot config log names each bearer
// token by its domain-separated logredact fingerprint, never by a bare
// sha256, which a derive convention can turn into a live credential
// (FOR-409).
func TestLogConfig_SecretsAsFingerprints(t *testing.T) {
	secrets := map[string]string{
		"APP_TOKEN":                    "app-token-value",
		"BOOTSTRAP_APP_TOKEN":          "bootstrap-token-value",
		"DELEGATION_COORDINATOR_TOKEN": "coordinator-token-value",
	}
	for name, value := range secrets {
		t.Setenv(name, value)
	}
	var logs bytes.Buffer
	LoadConfig().LogConfig(slog.New(slog.NewJSONHandler(&logs, nil)))
	out := logs.String()
	for name, value := range secrets {
		sum := sha256.Sum256([]byte(value))
		if bare := hex.EncodeToString(sum[:]); strings.Contains(out, bare[:logredact.FingerprintHexLen]) {
			t.Errorf("%s: bare sha256 logged:\n%s", name, out)
		}
		if strings.Contains(out, value) {
			t.Errorf("%s: raw value logged", name)
		}
		want := `"name":"` + name + `","value":"` + logredact.StringFingerprint(value) + `"`
		if !strings.Contains(out, want) {
			t.Errorf("%s: fingerprint not logged, want %s in:\n%s", name, want, out)
		}
	}
}
