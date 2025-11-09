package ranger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all 12-factor environment configuration
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

	// R2 Access Configuration
	R2BucketName string
	R2AccountID  string
	R2PublicURL  string

	// Deployment configuration (not from messages)
	TrustCanopy bool // If true, verify hash by reading object. If false, trust path hash.
}

var levelAliases = map[string]slog.Level{
	"debug":   slog.LevelDebug,
	"info":    slog.LevelInfo,
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
// It also returns a configured slog.Logger and the underlying slog.LevelVar so callers
// can adjust log levels at runtime if needed.
func LoadConfig() (Config, *slog.Logger, *slog.LevelVar) {
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

	// Parse TRUST_CANOPY: true if "true", "on", or non-zero integer
	trustCanopy := false
	trustEnv := strings.ToLower(strings.TrimSpace(os.Getenv("TRUST_CANOPY")))
	if trustEnv == "true" || trustEnv == "on" {
		trustCanopy = true
	} else if trustEnv != "" {
		// Try parsing as integer
		if val, err := strconv.Atoi(trustEnv); err == nil && val != 0 {
			trustCanopy = true
		}
	}

	// Build R2 public URL if components are provided
	r2PublicURL := os.Getenv("R2_PUBLIC_URL")
	if r2PublicURL == "" {
		accountID := os.Getenv("R2_ACCOUNT_ID")
		bucketName := os.Getenv("R2_BUCKET_NAME")
		if accountID != "" && bucketName != "" {
			r2PublicURL = fmt.Sprintf("https://%s.r2.cloudflarestorage.com/%s", accountID, bucketName)
		}
	}

	cfg := Config{
		Port:              getEnvOrDefault("PORT", "9090"),
		LogLevel:          getEnvOrDefault("LOG_LEVEL", "info"),
		ShutdownTimeout:   getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		QueueURL:          os.Getenv("RANGER_QUEUE_URL"),
		QueueAPIToken:     os.Getenv("RANGER_QUEUE_API_TOKEN"),
		QueueBatchSize:    getInt("RANGER_QUEUE_BATCH_SIZE", 1),
		PollInterval:      getDuration("POLL_INTERVAL", 5*time.Second),
		VisibilityTimeout: getDuration("VISIBILITY_TIMEOUT", 30*time.Second),
		R2BucketName:      os.Getenv("R2_BUCKET_NAME"),
		R2AccountID:       os.Getenv("R2_ACCOUNT_ID"),
		R2PublicURL:       r2PublicURL,
		TrustCanopy:       trustCanopy,
	}

	level, recognized := ParseLogLevel(cfg.LogLevel)
	logger, levelVar := NewLogger(level)

	if !recognized {
		logger.Warn("unrecognized log level value; defaulting to derived level", "input", cfg.LogLevel, "level", level.String())
	}

	logger.Debug("resolved log level", "input", cfg.LogLevel, "level", level.String())

	logConfigValue(logger, "RANGER_QUEUE_URL", cfg.QueueURL)
	logSecretDigest(logger, "RANGER_QUEUE_API_TOKEN", cfg.QueueAPIToken)
	logConfigValue(logger, "RANGER_QUEUE_BATCH_SIZE", cfg.QueueBatchSize)
	logConfigValue(logger, "POLL_INTERVAL", cfg.PollInterval)
	logConfigValue(logger, "VISIBILITY_TIMEOUT", cfg.VisibilityTimeout)

	return cfg, logger, levelVar
}

// Validate checks that all required configuration is present
func (c Config) Validate() error {
	if c.QueueURL == "" {
		return fmt.Errorf("RANGER_QUEUE_URL is required")
	}
	if c.QueueAPIToken == "" {
		return fmt.Errorf("RANGER_QUEUE_API_TOKEN is required")
	}
	if c.QueueBatchSize <= 0 {
		return fmt.Errorf("RANGER_QUEUE_BATCH_SIZE must be greater than zero")
	}
	if c.QueueBatchSize > 32 {
		return fmt.Errorf("RANGER_QUEUE_BATCH_SIZE must be 32 or less (Cloudflare limit)")
	}
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
		empty = false // cannot be "empty"
	case time.Duration:
		// Duration zero is not "empty" here
		v = val.String()
		empty = false
	default:
		// fallback: use fmt.Sprintf("%v")
		v = fmt.Sprintf("%v", val)
	}

	logger.Debug("config value", "name", name, "value", v, "empty", empty)
}
