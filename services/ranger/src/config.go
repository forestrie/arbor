package ranger

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

	// DO Ingress queue configuration
	// See: arbor/docs/arc-cloudflare-do-ingress.md
	QueueURL          string        // forestrie-ingress worker URL
	QueueToken        string        // Bearer token for pull/ack endpoints
	PollerId          string        // Unique identifier for this poller (auto-generated if empty)
	QueueBatchSize    int           // Maximum entries per pull request
	PollInterval      time.Duration // Interval between poll requests
	VisibilityTimeout time.Duration // Lease duration for pulled entries

	// R2 storage configuration (S3-compatible endpoint)
	R2URL   string
	R2Token string // Used to derive AWSSecretAccessKey when AWS_SECRET_ACCESS_KEY is not set

	// AWS credentials for SigV4 signing (Cloudflare R2)
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSRegion          string // Defaults to "auto" for Cloudflare R2

	// Deployment configuration
	SuppressAcknowledge bool   // Skip acks (for tests)
	WorkerCIDR          string // Snowflake worker CIDR, required
	PodIP               string // Pod IP address, required

	// Merklelog configuration
	MassifHeight    uint8  // Massif height (default 14)
	CommitmentEpoch uint32 // Commitment epoch (default 1)
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
// It also returns a configured slog.Logger and the underlying slog.LevelVar so callers
// can adjust log levels at runtime if needed.
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

	getUint8 := func(key string, defaultVal uint8) uint8 {
		if val := os.Getenv(key); val != "" {
			if parsed, err := strconv.ParseUint(val, 10, 8); err == nil {
				return uint8(parsed)
			}
		}
		return defaultVal
	}

	getUint32 := func(key string, defaultVal uint32) uint32 {
		if val := os.Getenv(key); val != "" {
			if parsed, err := strconv.ParseUint(val, 10, 32); err == nil {
				return uint32(parsed)
			}
		}
		return defaultVal
	}

	r2Token := getEnvOrDefault("R2_TOKEN", "")
	// fmt.Printf("R2_TOKEN len %d\n", len(r2Token))
	awsSecretAccessKey := getEnvOrDefault("AWS_SECRET_ACCESS_KEY", "")
	if awsSecretAccessKey == "" && r2Token != "" {
		// For Cloudflare compatibility Automatically derive AWS_SECRET_ACCESS_KEY
		// from R2_TOKEN when not explicitly set.
		sum := sha256.Sum256([]byte(r2Token))
		awsSecretAccessKey = hex.EncodeToString(sum[:])
	}

	cfg := Config{
		Port:               getEnvOrDefault("PORT", "9090"),
		LogLevel:           getEnvOrDefault("LOG_LEVEL", "info"),
		ShutdownTimeout:    getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		QueueURL:           os.Getenv("QUEUE_URL"),
		QueueToken:         os.Getenv("QUEUE_TOKEN"),
		PollerId:           os.Getenv("POLLER_ID"),
		QueueBatchSize:     getInt("QUEUE_BATCH_SIZE", 100),
		PollInterval:       getDuration("POLL_INTERVAL", 5*time.Second),
		VisibilityTimeout:  getDuration("VISIBILITY_TIMEOUT", 30*time.Second),
		R2URL:              os.Getenv("R2_URL"),
		R2Token:            r2Token,
		AWSAccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey: awsSecretAccessKey,
		AWSRegion:          getEnvOrDefault("AWS_REGION", "auto"),
		MassifHeight:       getUint8("MASSIF_HEIGHT", 14),
		CommitmentEpoch:    getUint32("COMMITMENT_EPOCH", 1),
		WorkerCIDR:         os.Getenv("WORKER_CIDR"),
		PodIP:              os.Getenv("POD_IP"),
	}

	return cfg
}

func (c Config) LogConfig(logger *slog.Logger) {
	logConfigValue(logger, "QUEUE_URL", c.QueueURL)
	logSecretDigest(logger, "QUEUE_TOKEN", c.QueueToken)
	logConfigValue(logger, "POLLER_ID", c.PollerId)
	logConfigValue(logger, "QUEUE_BATCH_SIZE", c.QueueBatchSize)
	logConfigValue(logger, "POLL_INTERVAL", c.PollInterval)
	logConfigValue(logger, "VISIBILITY_TIMEOUT", c.VisibilityTimeout)
	logConfigValue(logger, "R2_URL", c.R2URL)
	logSecretDigest(logger, "R2_TOKEN", c.R2Token)
	logConfigValue(logger, "AWS_ACCESS_KEY_ID", c.AWSAccessKeyID)
	logSecretDigest(logger, "AWS_SECRET_ACCESS_KEY", c.AWSSecretAccessKey)
	logConfigValue(logger, "AWS_REGION", c.AWSRegion)
	logConfigValue(logger, "MASSIF_HEIGHT", c.MassifHeight)
	logConfigValue(logger, "COMMITMENT_EPOCH", c.CommitmentEpoch)
	logConfigValue(logger, "WORKER_CIDR", c.WorkerCIDR)
	logConfigValue(logger, "POD_IP", c.PodIP)
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
	if c.R2URL == "" {
		return fmt.Errorf("R2_URL is required")
	}
	if c.AWSAccessKeyID == "" {
		return fmt.Errorf("AWS_ACCESS_KEY_ID is required for SigV4 signing")
	}
	if c.AWSSecretAccessKey == "" {
		return fmt.Errorf("AWS_SECRET_ACCESS_KEY is required (set AWS_SECRET_ACCESS_KEY or R2_TOKEN)")
	}
	if c.WorkerCIDR == "" {
		return fmt.Errorf("WORKER_CIDR is required")
	}
	if c.PodIP == "" {
		return fmt.Errorf("POD_IP is required")
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

	logger.Log(context.Background(), LevelNotice, "config value", "name", name, "value", v, "empty", empty)
}
