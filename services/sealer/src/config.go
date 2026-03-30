package sealer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// Config holds all 12-factor environment configuration.
type Config struct {
	// Service configuration
	Port            string
	LogLevel        string
	ShutdownTimeout time.Duration

	// Cloudflare Queue configuration (HTTP consumer pattern)
	QueueURL       string
	QueueToken     string
	QueueBatchSize int

	PollIntervalMin   time.Duration
	PollIntervalMax   time.Duration
	VisibilityTimeout time.Duration

	// Delegation signer / GCP Workload Identity configuration
	DelegationSignerServiceAccountEmail string
	DelegationSignerURL                 string
	DelegationLogIDPrefix               string
	DelegationKeyCurve                  string

	// R2 access configuration (S3-compatible endpoint)
	R2URL   string
	R2Token string // Used to derive AWSSecretAccessKey when AWS_SECRET_ACCESS_KEY is not set.

	// AWS Credentials for SigV4 signing (for S3-compatible APIs like Cloudflare R2)
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSRegion          string // Defaults to "auto" for Cloudflare R2
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

	r2Token := getEnvOrDefault("R2_TOKEN", "")
	awsSecretAccessKey := getEnvOrDefault("AWS_SECRET_ACCESS_KEY", "")
	if awsSecretAccessKey == "" && r2Token != "" {
		// Automatically derive AWS_SECRET_ACCESS_KEY from R2_TOKEN when not explicitly set.
		sum := sha256.Sum256([]byte(r2Token))
		awsSecretAccessKey = hex.EncodeToString(sum[:])
	}

	cfg := Config{
		Port:                                getEnvOrDefault("PORT", "9090"),
		LogLevel:                            getEnvOrDefault("LOG_LEVEL", "info"),
		ShutdownTimeout:                     getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		QueueURL:                            os.Getenv("QUEUE_URL"),
		QueueToken:                          os.Getenv("QUEUE_TOKEN"),
		QueueBatchSize:                      getInt("QUEUE_BATCH_SIZE", 31),
		PollIntervalMin:                     getDuration("POLL_INTERVAL_MIN", 0),
		PollIntervalMax:                     getDuration("POLL_INTERVAL_MAX", 5*time.Second),
		VisibilityTimeout:                   getDuration("VISIBILITY_TIMEOUT", 30*time.Second),
		DelegationSignerServiceAccountEmail: os.Getenv("DELEGATION_SIGNER_SERVICE_ACCOUNT_EMAIL"),
		DelegationSignerURL:                 os.Getenv("DELEGATION_SIGNER_URL"),
		DelegationLogIDPrefix:               os.Getenv("DELEGATION_LOG_ID_PREFIX"),
		DelegationKeyCurve:                  getEnvOrDefault("DELEGATION_KEY_CURVE", "secp256k1"),
		R2URL:                               os.Getenv("R2_URL"),
		R2Token:                             r2Token,
		AWSAccessKeyID:                      os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey:                  awsSecretAccessKey,
		AWSRegion:                           getEnvOrDefault("AWS_REGION", "auto"),
	}

	return cfg
}

func (c Config) LogConfig(logger *slog.Logger) {
	logConfigValue(logger, "QUEUE_URL", c.QueueURL)
	logSecretDigest(logger, "QUEUE_TOKEN", c.QueueToken)
	logConfigValue(logger, "QUEUE_BATCH_SIZE", c.QueueBatchSize)
	logConfigValue(logger, "POLL_INTERVAL_MIN", c.PollIntervalMin)
	logConfigValue(logger, "POLL_INTERVAL_MAX", c.PollIntervalMax)
	logConfigValue(logger, "VISIBILITY_TIMEOUT", c.VisibilityTimeout)
	logConfigValue(logger, "DELEGATION_SIGNER_SERVICE_ACCOUNT_EMAIL", c.DelegationSignerServiceAccountEmail)
	logConfigValue(logger, "DELEGATION_SIGNER_URL", c.DelegationSignerURL)
	logConfigValue(logger, "DELEGATION_LOG_ID_PREFIX", c.DelegationLogIDPrefix)
	logConfigValue(logger, "DELEGATION_KEY_CURVE", c.DelegationKeyCurve)
	logConfigValue(logger, "R2_URL", c.R2URL)
	logSecretDigest(logger, "R2_TOKEN", c.R2Token)
	logConfigValue(logger, "AWS_ACCESS_KEY_ID", c.AWSAccessKeyID)
	logSecretDigest(logger, "AWS_SECRET_ACCESS_KEY", c.AWSSecretAccessKey)
	logConfigValue(logger, "AWS_REGION", c.AWSRegion)
}

// Validate checks that all required configuration is present.
func (c Config) Validate() error {
	if c.QueueURL == "" {
		return fmt.Errorf("QUEUE_URL is required")
	}
	if c.QueueToken == "" {
		return fmt.Errorf("QUEUE_TOKEN is required")
	}
	if c.QueueBatchSize <= 0 {
		return fmt.Errorf("QUEUE_BATCH_SIZE must be greater than zero")
	}
	if c.QueueBatchSize > 32 {
		return fmt.Errorf("QUEUE_BATCH_SIZE must be 32 or less (Cloudflare limit)")
	}

	if c.DelegationSignerServiceAccountEmail == "" {
		return fmt.Errorf("DELEGATION_SIGNER_SERVICE_ACCOUNT_EMAIL is required")
	}
	if c.DelegationSignerURL == "" {
		return fmt.Errorf("DELEGATION_SIGNER_URL is required")
	}
	if err := validateHTTPSURL(c.DelegationSignerURL); err != nil {
		return fmt.Errorf("DELEGATION_SIGNER_URL is invalid: %w", err)
	}
	if _, err := delegationcert.ParseCurve(c.DelegationKeyCurve); err != nil {
		return fmt.Errorf("DELEGATION_KEY_CURVE is invalid: %w", err)
	}

	if c.R2URL == "" {
		return fmt.Errorf("R2_URL is required")
	}
	if c.AWSAccessKeyID == "" {
		return fmt.Errorf("AWS_ACCESS_KEY_ID is required for SigV4 signing")
	}
	if c.AWSSecretAccessKey == "" {
		return fmt.Errorf("AWS_SECRET_ACCESS_KEY is required for SigV4 signing (set AWS_SECRET_ACCESS_KEY or set R2_TOKEN to derive it)")
	}

	return nil
}

func validateHTTPSURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("empty")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("scheme must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
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
		empty = false
	case time.Duration:
		v = val.String()
		empty = false
	default:
		v = fmt.Sprintf("%v", val)
	}

	logger.Log(context.Background(), LevelNotice, "config value", "name", name, "value", v, "empty", empty)
}
