package univocity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds 12-factor configuration for the univocity trust-root service.
type Config struct {
	Port            string
	LogLevel        string
	ShutdownTimeout time.Duration

	RPCURLs map[uint64]string

	GenesisR2URL       string
	GenesisR2Token     string
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSRegion          string

	GenesisScanMinInterval time.Duration
	LogForestCacheSize     int
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

// LoadConfig loads configuration from environment variables. Misconfiguration is fatal.
func LoadConfig() (Config, error) {
	rpcURLs, err := parseRPCURLs(os.Getenv("UNIVOCITY_RPC_URLS"))
	if err != nil {
		return Config{}, err
	}

	genesisURL := strings.TrimSpace(os.Getenv("GENESIS_R2_URL"))
	if genesisURL == "" {
		return Config{}, errors.New("GENESIS_R2_URL is required")
	}

	r2Token := strings.TrimSpace(os.Getenv("R2_TOKEN"))
	awsAccessKey := strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID"))
	awsSecret := strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY"))
	if awsSecret == "" && r2Token != "" {
		sum := sha256.Sum256([]byte(r2Token))
		awsSecret = hex.EncodeToString(sum[:])
	}
	if awsAccessKey == "" {
		return Config{}, errors.New("AWS_ACCESS_KEY_ID is required for genesis R2 read")
	}
	if awsSecret == "" {
		return Config{}, errors.New(
			"AWS_SECRET_ACCESS_KEY is required (set AWS_SECRET_ACCESS_KEY or R2_TOKEN)",
		)
	}

	scanInterval := getDurationSeconds("GENESIS_SCAN_MIN_INTERVAL", 60)
	cacheSize := getIntPositive("LOG_FOREST_CACHE_SIZE", 10000)

	return Config{
		Port:                   getEnvOrDefault("PORT", "9091"),
		LogLevel:               getEnvOrDefault("LOG_LEVEL", "info"),
		ShutdownTimeout:        getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		RPCURLs:                rpcURLs,
		GenesisR2URL:           genesisURL,
		GenesisR2Token:         r2Token,
		AWSAccessKeyID:         awsAccessKey,
		AWSSecretAccessKey:     awsSecret,
		AWSRegion:              getEnvOrDefault("AWS_REGION", "auto"),
		GenesisScanMinInterval: scanInterval,
		LogForestCacheSize:     cacheSize,
	}, nil
}

func parseRPCURLs(raw string) (map[uint64]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("UNIVOCITY_RPC_URLS is required")
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("UNIVOCITY_RPC_URLS: invalid JSON: %w", err)
	}
	if len(m) == 0 {
		return nil, errors.New("UNIVOCITY_RPC_URLS must define at least one chain")
	}
	out := make(map[uint64]string, len(m))
	for k, v := range m {
		id, err := strconv.ParseUint(k, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("UNIVOCITY_RPC_URLS: invalid chainId key %q: %w", k, err)
		}
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("UNIVOCITY_RPC_URLS: empty rpc url for chainId %q", k)
		}
		out[id] = v
	}
	return out, nil
}

// LogConfig logs non-secret configuration values for observability.
func (c Config) LogConfig(logger *slog.Logger) {
	chainIDs := make([]uint64, 0, len(c.RPCURLs))
	for id := range c.RPCURLs {
		chainIDs = append(chainIDs, id)
	}
	logger.Info("config",
		"PORT", c.Port,
		"LOG_LEVEL", c.LogLevel,
		"SHUTDOWN_TIMEOUT", c.ShutdownTimeout,
		"RPC_CHAIN_IDS", chainIDs,
		"GENESIS_R2_URL", nonSecret(c.GenesisR2URL),
		"GENESIS_SCAN_MIN_INTERVAL", c.GenesisScanMinInterval,
		"LOG_FOREST_CACHE_SIZE", c.LogForestCacheSize,
	)
}

func nonSecret(s string) string {
	if s == "" {
		return ""
	}
	return "(set)"
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getDuration(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}

func getDurationSeconds(key string, defaultSeconds int) time.Duration {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return time.Duration(defaultSeconds) * time.Second
}

func getIntPositive(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			return n
		}
	}
	return defaultVal
}
