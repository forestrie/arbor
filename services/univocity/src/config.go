package univocity

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds 12-factor configuration for the univocity auth-log status service.
type Config struct {
	Port                     string
	LogLevel                 string
	ShutdownTimeout          time.Duration
	UnivocityRPCURL          string
	UnivocityContractAddress string
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
	return Config{
		Port:                     getEnvOrDefault("PORT", "9091"),
		LogLevel:                 getEnvOrDefault("LOG_LEVEL", "info"),
		ShutdownTimeout:          getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		UnivocityRPCURL:          os.Getenv("UNIVOCITY_RPC_URL"),
		UnivocityContractAddress: os.Getenv("UNIVOCITY_CONTRACT_ADDRESS"),
	}
}

// LogConfig logs non-secret configuration values for observability.
func (c Config) LogConfig(logger *slog.Logger) {
	logger.Info("config", "PORT", c.Port, "LOG_LEVEL", c.LogLevel, "SHUTDOWN_TIMEOUT", c.ShutdownTimeout)
	logger.Info("config", "UNIVOCITY_RPC_URL", nonSecret(c.UnivocityRPCURL), "UNIVOCITY_CONTRACT_ADDRESS", nonSecret(c.UnivocityContractAddress))
}

func nonSecret(s string) string {
	if s == "" {
		return ""
	}
	return "(set)"
}
