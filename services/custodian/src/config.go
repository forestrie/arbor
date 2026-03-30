package custodian

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds 12-factor configuration for custodian.
type Config struct {
	Port            string
	LogLevel        string
	ShutdownTimeout time.Duration

	// Application tokens (Bearer); log only digests.
	AppToken          string // Normal: key creation, list keys, public key, custody key signing
	BootstrapAppToken string // Bootstrap: key destruction, POST .../:bootstrap/sign

	// GCP: custody signer SA (IAM grants per key) and custody key ring for key creation.
	CustodySignerSAEmail string
	CustodyKeyRingID     string // Full key ring ID (projects/.../locations/.../keyRings/...)
	// BootstrapKMSCryptoKeyID is the full KMS CryptoKey resource for alias :bootstrap (not custody ring).
	BootstrapKMSCryptoKeyID string
	GCPProjectID            string // Project ID (for KMS API)
	GCPLocation             string // Location (e.g. europe-west2)

	// RootLogID (lowercase hex) for KMS list miss → :bootstrap when bootstrap is not in custody ring.
	RootLogID string
	// LogIDCacheSize caps in-memory log id → key id LRU.
	// Default 1024 when LOG_ID_CACHE_SIZE is unset; set env to "0" to disable.
	LogIDCacheSize int
}

const defaultLogIDCacheSize = 1024

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

	logCache := defaultLogIDCacheSize
	if raw := strings.TrimSpace(os.Getenv("LOG_ID_CACHE_SIZE")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			logCache = n
		}
	}

	return Config{
		Port:                    getEnvOrDefault("PORT", "9092"),
		LogLevel:                getEnvOrDefault("LOG_LEVEL", "info"),
		ShutdownTimeout:         getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		AppToken:                os.Getenv("APP_TOKEN"),
		BootstrapAppToken:       os.Getenv("BOOTSTRAP_APP_TOKEN"),
		CustodySignerSAEmail:    os.Getenv("CUSTODY_SIGNER_SA_EMAIL"),
		CustodyKeyRingID:        os.Getenv("CUSTODY_KEY_RING_ID"),
		BootstrapKMSCryptoKeyID: os.Getenv("BOOTSTRAP_KMS_CRYPTO_KEY_ID"),
		GCPProjectID:            os.Getenv("GCP_PROJECT_ID"),
		GCPLocation:             getEnvOrDefault("GCP_LOCATION", "europe-west2"),
		RootLogID:               strings.TrimSpace(os.Getenv("ROOT_LOG_ID")),
		LogIDCacheSize:          logCache,
	}
}

// LogConfig logs non-secret configuration values for observability.
func (c Config) LogConfig(logger *slog.Logger) {
	logger.Warn("config value", "name", "PORT", "value", c.Port)
	logger.Warn("config value", "name", "LOG_LEVEL", "value", c.LogLevel)
	logger.Warn("config value", "name", "SHUTDOWN_TIMEOUT", "value", c.ShutdownTimeout.String())
	logger.Warn("config value", "name", "APP_TOKEN", "value", secretDigest(c.AppToken))
	logger.Warn("config value", "name", "BOOTSTRAP_APP_TOKEN", "value", secretDigest(c.BootstrapAppToken))
	logger.Warn("config value", "name", "CUSTODY_SIGNER_SA_EMAIL", "value", c.CustodySignerSAEmail)
	logger.Warn("config value", "name", "CUSTODY_KEY_RING_ID", "value", c.CustodyKeyRingID)
	logger.Warn("config value", "name", "BOOTSTRAP_KMS_CRYPTO_KEY_ID", "value", c.BootstrapKMSCryptoKeyID)
	logger.Warn("config value", "name", "GCP_PROJECT_ID", "value", c.GCPProjectID)
	logger.Warn("config value", "name", "GCP_LOCATION", "value", c.GCPLocation)
	logger.Warn("config value", "name", "ROOT_LOG_ID", "value", c.RootLogID)
	logger.Warn("config value", "name", "LOG_ID_CACHE_SIZE", "value", c.LogIDCacheSize)
}

func secretDigest(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
