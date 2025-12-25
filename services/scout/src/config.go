package scout

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds 12-factor configuration for scout.
type Config struct {
	Port            string
	LogLevel        string
	ShutdownTimeout time.Duration

	// R2 access configuration (S3-compatible endpoint)
	R2URL   string
	R2Token string // Used to derive AWSSecretAccessKey when AWS_SECRET_ACCESS_KEY is not set.

	// AWS credentials for SigV4 signing (for S3-compatible APIs like Cloudflare R2)
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSRegion          string
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

// NewLogger builds a JSON slog.Logger configured with the provided level.
func NewLogger(level slog.Level) (*slog.Logger, *slog.LevelVar) {
	var levelVar slog.LevelVar
	levelVar.Set(level)

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: &levelVar})
	return slog.New(handler), &levelVar
}

// LoadConfig loads configuration from environment variables with defaults.
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

	r2Token := getEnvOrDefault("R2_TOKEN", "")
	awsSecretAccessKey := getEnvOrDefault("AWS_SECRET_ACCESS_KEY", "")
	if awsSecretAccessKey == "" && r2Token != "" {
		// Automatically derive AWS_SECRET_ACCESS_KEY from R2_TOKEN when not explicitly set.
		sum := sha256.Sum256([]byte(r2Token))
		awsSecretAccessKey = hex.EncodeToString(sum[:])
	}

	return Config{
		Port:               getEnvOrDefault("PORT", "9090"),
		LogLevel:           getEnvOrDefault("LOG_LEVEL", "info"),
		ShutdownTimeout:    getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		R2URL:              os.Getenv("R2_URL"),
		R2Token:            r2Token,
		AWSAccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey: awsSecretAccessKey,
		AWSRegion:          getEnvOrDefault("AWS_REGION", "auto"),
	}
}

// LogConfig logs non-secret configuration values for observability.
// For secret values, it logs a SHA256 digest to avoid leaking secrets.
func (c Config) LogConfig(logger *slog.Logger) {
	logger.Warn("config value", "name", "PORT", "value", c.Port)
	logger.Warn("config value", "name", "LOG_LEVEL", "value", c.LogLevel)
	logger.Warn("config value", "name", "SHUTDOWN_TIMEOUT", "value", c.ShutdownTimeout.String())
	logger.Warn("config value", "name", "R2_URL", "value", c.R2URL)
	logger.Warn("config value", "name", "R2_TOKEN", "value", secretDigest(c.R2Token))
	logger.Warn("config value", "name", "AWS_ACCESS_KEY_ID", "value", c.AWSAccessKeyID)
	logger.Warn("config value", "name", "AWS_SECRET_ACCESS_KEY", "value", secretDigest(c.AWSSecretAccessKey))
	logger.Warn("config value", "name", "AWS_REGION", "value", c.AWSRegion)
}

func secretDigest(value string) string {
	if value == "" {
		return ""
	}
	// sha256 is used for display only; do not rely on this for cryptographic purposes.
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
