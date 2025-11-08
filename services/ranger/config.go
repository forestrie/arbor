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

// LoadConfig loads configuration from environment variables with sensible defaults
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

	logConfigValue("RANGER_QUEUE_URL", cfg.QueueURL)
	logSecretDigest("RANGER_QUEUE_API_TOKEN", cfg.QueueAPIToken)
	logConfigInt("RANGER_QUEUE_BATCH_SIZE", cfg.QueueBatchSize)
	logConfigDuration("POLL_INTERVAL", cfg.PollInterval)
	logConfigDuration("VISIBILITY_TIMEOUT", cfg.VisibilityTimeout)

	return cfg
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

func logConfigValue(name, value string) {
	if value == "" {
		slog.Info("config value", "name", name, "value", "", "empty", true)
		return
	}
	slog.Info("config value", "name", name, "value", value, "empty", false)
}

func logConfigInt(name string, value int) {
	slog.Info("config value", "name", name, "value", value)
}

func logConfigDuration(name string, value time.Duration) {
	slog.Info("config value", "name", name, "value", value.String())
}

func logSecretDigest(name, value string) {
	if value == "" {
		slog.Info("config secret empty", "name", name, "empty", true)
		return
	}
	sum := sha256.Sum256([]byte(value))
	slog.Info("config secret sha256",
		"name", name,
		"sha256", hex.EncodeToString(sum[:]),
		"empty", false,
	)
}
