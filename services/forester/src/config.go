package forester

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all 12-factor environment configuration.
type Config struct {
	// Service configuration
	Port            string
	LogLevel        string
	ShutdownTimeout time.Duration

	// Cloudflare Queue configuration
	QueueURL          string
	QueueAPIToken     string
	QueueBatchSize    int
	PollInterval      time.Duration
	VisibilityTimeout time.Duration

	// Cloudflare KV configuration (wired for future use; not required yet)
	CloudflareAccountID         string
	RangerMMRIndexNamespaceID   string
	RangerMMRMassifsNamespaceID string
	KVAPIToken                  string
}

// LevelNotice is a custom log level between INFO (0) and WARN (4).
// When set as the log level, it excludes INFO and below, but includes WARN and ERROR.
const LevelNotice slog.Level = 2

var levelAliases = map[string]slog.Level{
	"debug":   slog.LevelDebug,
	"info":    slog.LevelInfo,
	"notice":  LevelNotice,
	"warn":    slog.LevelWarn,
	"warning": slog.LevelWarn,
	"error":   slog.LevelError,
}

// ParseLogLevel converts a string level to an slog.Level. Returns the parsed level and
// whether the input matched a named level (non-numeric).
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

// NewLogger builds a JSON slog.Logger configured with the provided level via slog.LevelVar.
func NewLogger(level slog.Level) (*slog.Logger, *slog.LevelVar) {
	var levelVar slog.LevelVar
	levelVar.Set(level)

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: &levelVar,
	})

	return slog.New(handler), &levelVar
}

// LoadConfig loads configuration from environment variables with sensible defaults.
func LoadConfig() Config {
	getEnvOrDefault := func(key, defaultVal string) string {
		if val := os.Getenv(key); val != "" {
			return val
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

	getInt := func(key string, defaultVal int) int {
		if val := os.Getenv(key); val != "" {
			if parsed, err := strconv.Atoi(val); err == nil {
				return parsed
			}
		}
		return defaultVal
	}

	cfg := Config{
		Port:                        getEnvOrDefault("PORT", "9090"),
		LogLevel:                    getEnvOrDefault("LOG_LEVEL", "info"),
		ShutdownTimeout:             getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		QueueURL:                    os.Getenv("FORESTER_QUEUE_URL"),
		QueueAPIToken:               os.Getenv("FORESTER_QUEUE_API_TOKEN"),
		QueueBatchSize:              getInt("FORESTER_QUEUE_BATCH_SIZE", 1),
		PollInterval:                getDuration("POLL_INTERVAL", 5*time.Second),
		VisibilityTimeout:           getDuration("VISIBILITY_TIMEOUT", 30*time.Second),
		CloudflareAccountID:         os.Getenv("CLOUDFLARE_ACCOUNT_ID"),
		RangerMMRIndexNamespaceID:   os.Getenv("RANGER_MMR_INDEX_NAMESPACE_ID"),
		RangerMMRMassifsNamespaceID: os.Getenv("RANGER_MMR_MASSIFS_NAMESPACE_ID"),
		KVAPIToken:                  os.Getenv("FORESTER_KV_API_TOKEN"),
	}

	return cfg
}

func (c Config) LogConfig(logger *slog.Logger) {
	logConfigValue(logger, "FORESTER_QUEUE_URL", c.QueueURL)
	logSecretDigest(logger, "FORESTER_QUEUE_API_TOKEN", c.QueueAPIToken)
	logConfigValue(logger, "FORESTER_QUEUE_BATCH_SIZE", c.QueueBatchSize)
	logConfigValue(logger, "POLL_INTERVAL", c.PollInterval)
	logConfigValue(logger, "VISIBILITY_TIMEOUT", c.VisibilityTimeout)

	logConfigValue(logger, "CLOUDFLARE_ACCOUNT_ID", c.CloudflareAccountID)
	logConfigValue(logger, "RANGER_MMR_INDEX_NAMESPACE_ID", c.RangerMMRIndexNamespaceID)
	logConfigValue(logger, "RANGER_MMR_MASSIFS_NAMESPACE_ID", c.RangerMMRMassifsNamespaceID)
	logSecretDigest(logger, "FORESTER_KV_API_TOKEN", c.KVAPIToken)
}

// Validate checks that all required configuration is present.
func (c Config) Validate() error {
	if c.QueueURL == "" {
		return fmt.Errorf("FORESTER_QUEUE_URL is required")
	}
	if c.QueueAPIToken == "" {
		return fmt.Errorf("FORESTER_QUEUE_API_TOKEN is required")
	}
	if c.QueueBatchSize <= 0 {
		return fmt.Errorf("FORESTER_QUEUE_BATCH_SIZE must be greater than zero")
	}
	if c.QueueBatchSize > 32 {
		return fmt.Errorf("FORESTER_QUEUE_BATCH_SIZE must be 32 or less (Cloudflare limit)")
	}

	// KV configuration is intentionally not required yet (future work).
	return nil
}

func logSecretDigest(logger *slog.Logger, name, value string) {
	var digest string
	if value == "" {
		digest = ""
	} else {
		sum := sha256.Sum256([]byte(value))
		digest = hex.EncodeToString(sum[:])
	}
	logConfigValue(logger, name, digest)
}

func logConfigValue[T any](logger *slog.Logger, name string, value T) {
	var v any = value
	empty := false

	switch val := any(value).(type) {
	case string:
		empty = val == ""
		if empty {
			v = ""
		}
	case int:
		empty = false
	case time.Duration:
		v = val.String()
		empty = false
	default:
		v = fmt.Sprintf("%v", val)
	}

	logger.Log(context.Background(), LevelNotice, "config value", "name", name, "value", v, "empty", empty)
}
