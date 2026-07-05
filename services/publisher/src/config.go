package publisher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/logredact"
)

// Config holds all 12-factor environment configuration for the publisher.
//
// Per plan-2607-02 / ADR-0034 the publisher is multi-forest and multi-chain: it
// does NOT take a single UNIVOCITY_CONTRACT_ADDRESS / UNIVOCITY_CHAIN_ID.
// Instead it resolves each checkpoint's (chainId, contract) from public R2
// genesis (ADR-0047) and submits to that chain's RPC, keyed by UNIVOCITY_RPC_URLS.
type Config struct {
	// Service configuration
	Port            string
	LogLevel        string
	ShutdownTimeout time.Duration

	// Cloudflare Queue configuration (HTTP consumer pattern, checkpoints prefix)
	QueueURL       string
	QueueToken     string
	QueueBatchSize int

	PollIntervalMin   time.Duration
	PollIntervalMax   time.Duration
	VisibilityTimeout time.Duration

	// Multi-chain RPC endpoints: chainId (decimal) -> rpc url. A forest whose
	// resolved chain is absent from this map is skipped with an alert (D3),
	// never wedging the queue.
	RPCURLs map[uint64]string

	// PublisherKeyHex is the gas-only EOA private key (hex, no 0x prefix
	// required). Same address on every EVM chain, funded per chain. Authority
	// stays with the grant/signature chain — "postmark, not gatekeeper".
	PublisherKeyHex string

	// GrantStoreURL is the anonymous public base URL for the univocity-owned
	// grant store and forest genesis objects (ResolveForestContract +
	// ReadStoredGrant). Falls back to R2URL when unset.
	GrantStoreURL string

	// R2 access configuration (S3-compatible endpoint) for massif + checkpoint
	// object reads.
	R2URL   string
	R2Token string // Used to derive AWSSecretAccessKey when AWS_SECRET_ACCESS_KEY is not set.

	// AWS Credentials for SigV4 signing (for S3-compatible APIs like Cloudflare R2)
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSRegion          string // Defaults to "auto" for Cloudflare R2
}

// LevelNotice is a custom log level between INFO (0) and WARN (4).
const LevelNotice slog.Level = 2

var levelAliases = map[string]slog.Level{
	"debug":   slog.LevelDebug,
	"info":    slog.LevelInfo,
	"notice":  LevelNotice,
	"warn":    slog.LevelWarn,
	"warning": slog.LevelWarn,
	"error":   slog.LevelError,
}

// ParseLogLevel converts a string level to an slog.Level. Returns the parsed
// level and whether the input matched a named level (non-numeric).
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

// LoadConfig loads configuration from environment variables with sensible
// defaults. Invalid UNIVOCITY_RPC_URLS is surfaced by Validate, not here, so
// LoadConfig stays panic-free for the CLI path.
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
		sum := sha256.Sum256([]byte(r2Token))
		awsSecretAccessKey = hex.EncodeToString(sum[:])
	}

	// Parse errors are deferred to Validate; a nil map there fails cleanly.
	rpcURLs, _ := parseRPCURLs(os.Getenv("UNIVOCITY_RPC_URLS"))

	cfg := Config{
		Port:               getEnvOrDefault("PORT", "9090"),
		LogLevel:           getEnvOrDefault("LOG_LEVEL", "info"),
		ShutdownTimeout:    getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		QueueURL:           os.Getenv("QUEUE_URL"),
		QueueToken:         os.Getenv("QUEUE_TOKEN"),
		QueueBatchSize:     getInt("QUEUE_BATCH_SIZE", 31),
		PollIntervalMin:    getDuration("POLL_INTERVAL_MIN", 0),
		PollIntervalMax:    getDuration("POLL_INTERVAL_MAX", 5*time.Second),
		VisibilityTimeout:  getDuration("VISIBILITY_TIMEOUT", 30*time.Second),
		RPCURLs:            rpcURLs,
		PublisherKeyHex:    os.Getenv("PUBLISHER_EOA_KEY"),
		GrantStoreURL:      os.Getenv("GRANT_STORE_URL"),
		R2URL:              os.Getenv("R2_URL"),
		R2Token:            r2Token,
		AWSAccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey: awsSecretAccessKey,
		AWSRegion:          getEnvOrDefault("AWS_REGION", "auto"),
	}
	if cfg.GrantStoreURL == "" {
		cfg.GrantStoreURL = cfg.R2URL
	}
	return cfg
}

// parseRPCURLs decodes the UNIVOCITY_RPC_URLS JSON object {"<chainId>": "<url>"}
// into a chainId->url map. Ported from the univocity read service so the two
// services share one config surface (ADR-0034).
func parseRPCURLs(raw string) (map[uint64]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("UNIVOCITY_RPC_URLS is required")
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("UNIVOCITY_RPC_URLS: invalid JSON: %w", err)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("UNIVOCITY_RPC_URLS must define at least one chain")
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

func (c Config) LogConfig(logger *slog.Logger) {
	logConfigValue(logger, "QUEUE_URL", c.QueueURL)
	logSecretDigest(logger, "QUEUE_TOKEN", c.QueueToken)
	logConfigValue(logger, "QUEUE_BATCH_SIZE", c.QueueBatchSize)
	logConfigValue(logger, "POLL_INTERVAL_MIN", c.PollIntervalMin)
	logConfigValue(logger, "POLL_INTERVAL_MAX", c.PollIntervalMax)
	logConfigValue(logger, "VISIBILITY_TIMEOUT", c.VisibilityTimeout)
	logConfigValue(logger, "UNIVOCITY_RPC_URLS_CHAINS", len(c.RPCURLs))
	for id, u := range c.RPCURLs {
		logConfigValue(logger, fmt.Sprintf("UNIVOCITY_RPC_URL[%d]", id), u)
	}
	logSecretDigest(logger, "PUBLISHER_EOA_KEY", c.PublisherKeyHex)
	logConfigValue(logger, "GRANT_STORE_URL", c.GrantStoreURL)
	logConfigValue(logger, "R2_URL", c.R2URL)
	logSecretDigest(logger, "R2_TOKEN", c.R2Token)
	logSecretDigest(logger, "AWS_ACCESS_KEY_ID", c.AWSAccessKeyID)
	logSecretDigest(logger, "AWS_SECRET_ACCESS_KEY", c.AWSSecretAccessKey)
	logConfigValue(logger, "AWS_REGION", c.AWSRegion)
}

// Validate checks that all required configuration is present. It has two modes:
// ValidateCLI covers the one-shot publish path (no queue needed); Validate adds
// the queue requirements for the daemon.
func (c Config) Validate() error {
	if err := c.ValidateCLI(); err != nil {
		return err
	}
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
	return nil
}

// ValidateCLI checks the configuration required to assemble and submit a single
// checkpoint (no queue). Used by the `publish` CLI subcommand.
func (c Config) ValidateCLI() error {
	if _, err := parseRPCURLs(rpcURLsJSON(c.RPCURLs)); err != nil {
		return err
	}
	if strings.TrimSpace(c.PublisherKeyHex) == "" {
		return fmt.Errorf("PUBLISHER_EOA_KEY is required (gas-only publisher EOA)")
	}
	if _, err := parsePublisherKey(c.PublisherKeyHex); err != nil {
		return fmt.Errorf("PUBLISHER_EOA_KEY is invalid: %w", err)
	}
	if c.GrantStoreURL == "" {
		return fmt.Errorf("GRANT_STORE_URL (or R2_URL) is required for grant/genesis resolution")
	}
	if err := validateHTTPSURL(c.GrantStoreURL); err != nil {
		return fmt.Errorf("GRANT_STORE_URL is invalid: %w", err)
	}
	if c.R2URL == "" {
		return fmt.Errorf("R2_URL is required")
	}
	if c.AWSAccessKeyID == "" {
		return fmt.Errorf("AWS_ACCESS_KEY_ID is required for SigV4 signing")
	}
	if c.AWSSecretAccessKey == "" {
		return fmt.Errorf("AWS_SECRET_ACCESS_KEY is required for SigV4 signing (set AWS_SECRET_ACCESS_KEY or R2_TOKEN to derive it)")
	}
	return nil
}

// rpcURLsJSON re-serialises the parsed map so ValidateCLI can reuse parseRPCURLs
// for the "at least one chain" / non-empty checks even when RPCURLs was set
// programmatically (e.g. in tests).
func rpcURLsJSON(m map[uint64]string) string {
	if len(m) == 0 {
		return ""
	}
	sm := make(map[string]string, len(m))
	for id, u := range m {
		sm[strconv.FormatUint(id, 10)] = u
	}
	b, _ := json.Marshal(sm)
	return string(b)
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
	logConfigValue(logger, name, logredact.StringSHA256Hex(value))
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
