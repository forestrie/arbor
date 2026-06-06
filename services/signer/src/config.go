package signer

import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds 12-factor configuration for the signer (Plan 0004 subplan 04).
type Config struct {
	Port            string
	LogLevel        string
	ShutdownTimeout time.Duration

	// Bootstrap key: GCP KMS key resource name (e.g. projects/P/locations/L/keyRings/R/cryptoKeys/K).
	// Must exist in KMS before univocity contract deploy/init.
	BootstrapKeyID string

	// Optional: univocity auth-log status base URL for resolving root and parent key.
	// When set, /delegate/parent can resolve parent_log_id == root to bootstrap key.
	UnivocityURL string

	// Optional: JSON map of parent log id (canonical UUID or 32-hex) to KMS key name.
	// When parent is not the root, key is looked up here; if unset and parent != root, 404.
	ParentKeysJSON string
}

// ParentKeyMap parses ParentKeysJSON into a map. Returns nil if empty or invalid.
func (c Config) ParentKeyMap() map[string]string {
	s := strings.TrimSpace(c.ParentKeysJSON)
	if s == "" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}

var levelAliases = map[string]slog.Level{
	"debug":   slog.LevelDebug,
	"info":    slog.LevelInfo,
	"warn":    slog.LevelWarn,
	"warning": slog.LevelWarn,
	"error":   slog.LevelError,
}

// ParseLogLevel converts a string level to slog.Level.
func ParseLogLevel(raw string) (slog.Level, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return slog.LevelInfo, true
	}
	if lvl, ok := levelAliases[trimmed]; ok {
		return lvl, true
	}
	if numeric, err := strconv.Atoi(trimmed); err == nil {
		return slog.Level(numeric), true
	}
	return slog.LevelInfo, false
}

// NewLogger builds a JSON slog.Logger.
func NewLogger(level slog.Level) (*slog.Logger, *slog.LevelVar) {
	var levelVar slog.LevelVar
	levelVar.Set(level)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: &levelVar})
	return slog.New(handler), &levelVar
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() Config {
	getEnv := func(key, defaultVal string) string {
		if val := os.Getenv(key); val != "" {
			return strings.TrimSpace(val)
		}
		return defaultVal
	}
	getDuration := func(key string, defaultVal time.Duration) time.Duration {
		if val := os.Getenv(key); val != "" {
			if d, err := time.ParseDuration(val); err == nil {
				return d
			}
		}
		return defaultVal
	}
	return Config{
		Port:            getEnv("PORT", "9092"),
		LogLevel:        getEnv("LOG_LEVEL", "info"),
		ShutdownTimeout: getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		BootstrapKeyID:  strings.TrimSpace(os.Getenv("SIGNER_BOOTSTRAP_KEY_ID")),
		UnivocityURL:    strings.TrimSpace(os.Getenv("SIGNER_UNIVOCITY_URL")),
		ParentKeysJSON:  os.Getenv("SIGNER_PARENT_KEYS"),
	}
}

// LogConfig logs non-secret configuration.
func (c Config) LogConfig(logger *slog.Logger) {
	logger.Info("config", "PORT", c.Port, "LOG_LEVEL", c.LogLevel)
	logger.Info("config", "SIGNER_BOOTSTRAP_KEY_ID", nonSecret(c.BootstrapKeyID))
	logger.Info("config", "SIGNER_UNIVOCITY_URL", nonSecret(c.UnivocityURL))
	if c.ParentKeyMap() != nil {
		logger.Info("config", "SIGNER_PARENT_KEYS", "(set)")
	}
}

func nonSecret(s string) string {
	if s == "" {
		return ""
	}
	return "(set)"
}
