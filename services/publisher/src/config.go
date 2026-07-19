package publisher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
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

	// GrantStoreURL is the anonymous public-read base URL for the
	// univocity-owned grant store and forest genesis objects
	// (ResolveForestContract + ReadStoredGrant, via PublicBucketGetter — no
	// SigV4). It must be the public bucket domain, NOT R2URL (the SigV4 S3-API
	// endpoint): anonymous GETs against the S3 endpoint of a credentialed bucket
	// return 403. No fallback to R2URL (P3).
	GrantStoreURL string

	// On-chain submission tuning (P13 — operational constants, not baked in).
	// publishCheckpoint gas is predictable, so we use a fixed limit rather than
	// EstimateGas. Transactions are EIP-1559 (DynamicFeeTx). When both fee caps
	// are set they pin the fee and skip the SuggestGasTipCap/base-fee reads;
	// otherwise the tip is suggested and the fee cap derived from the base fee.
	GasLimit                uint64
	MaxFeePerGasWei         *big.Int
	MaxPriorityFeePerGasWei *big.Int
	ReceiptTimeout          time.Duration
	ReceiptPollInterval     time.Duration

	// OwnerWait bounds the in-cycle drain for owner_not_anchored groups: a child
	// checkpoint whose owner (authority log) is not yet on-chain is held and
	// re-assembled against fresh logState until the owner anchors or this bound
	// elapses, then released to redeliver. Zero disables the drain (release
	// immediately, the pre-FOR-395 behaviour). OwnerPoll is the re-assembly
	// interval. See plan-2607-06.
	OwnerWait time.Duration
	OwnerPoll time.Duration

	// ResyncInterval enables the notification-loss backstop (plan-2607-07): a
	// periodic sweep that lists the checkpoints prefix and re-drives the
	// one-shot publish for any seal not yet anchored, so a lost R2 event
	// notification can never permanently strand a forest. Zero (the default)
	// disables the sweep — rollout is inert until GitOps sets RESYNC_INTERVAL
	// (the sealer's equivalent backstop defaults on; the publisher starts
	// inert per plan-2607-07 §4). While enabled, owner_not_anchored messages
	// are acked instead of redelivered to the retry cliff — the sweep is the
	// reconciliation mechanism. ResyncPageSize bounds each list page.
	ResyncInterval time.Duration
	ResyncPageSize int

	// Queue poll backoff tuning.
	BackoffBase time.Duration
	PollJitter  float64 // fraction of the sleep applied as ± jitter (e.g. 0.1)

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

	getUint64 := func(key string, defaultVal uint64) uint64 {
		if val := os.Getenv(key); val != "" {
			if parsed, err := strconv.ParseUint(val, 10, 64); err == nil {
				return parsed
			}
		}
		return defaultVal
	}

	getFloat := func(key string, defaultVal float64) float64 {
		if val := os.Getenv(key); val != "" {
			if parsed, err := strconv.ParseFloat(val, 64); err == nil {
				return parsed
			}
		}
		return defaultVal
	}

	// EIP-1559 fee caps are decimal wei strings; empty -> derive from the chain.
	parseWei := func(key string) *big.Int {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			if p, ok := new(big.Int).SetString(v, 10); ok {
				return p
			}
		}
		return nil
	}
	maxFeeWei := parseWei("PUBLISHER_MAX_FEE_PER_GAS")
	maxPriorityWei := parseWei("PUBLISHER_MAX_PRIORITY_FEE")

	r2Token := getEnvOrDefault("R2_TOKEN", "")
	awsSecretAccessKey := getEnvOrDefault("AWS_SECRET_ACCESS_KEY", "")
	if awsSecretAccessKey == "" && r2Token != "" {
		sum := sha256.Sum256([]byte(r2Token))
		awsSecretAccessKey = hex.EncodeToString(sum[:])
	}

	// Parse errors are deferred to Validate; a nil map there fails cleanly.
	rpcURLs, _ := parseRPCURLs(os.Getenv("UNIVOCITY_RPC_URLS"))

	cfg := Config{
		Port:            getEnvOrDefault("PORT", "9090"),
		LogLevel:        getEnvOrDefault("LOG_LEVEL", "info"),
		ShutdownTimeout: getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		QueueURL:        os.Getenv("QUEUE_URL"),
		QueueToken:      os.Getenv("QUEUE_TOKEN"),
		QueueBatchSize:  getInt("QUEUE_BATCH_SIZE", 31),
		PollIntervalMin: getDuration("POLL_INTERVAL_MIN", 0),
		PollIntervalMax: getDuration("POLL_INTERVAL_MAX", 5*time.Second),
		// Default visibility must exceed ReceiptTimeout so a slow-to-mine tx is
		// resolved before the queue redelivers it (P5).
		VisibilityTimeout:       getDuration("VISIBILITY_TIMEOUT", 90*time.Second),
		GasLimit:                getUint64("PUBLISHER_GAS_LIMIT", 3_000_000),
		MaxFeePerGasWei:         maxFeeWei,
		MaxPriorityFeePerGasWei: maxPriorityWei,
		ReceiptTimeout:          getDuration("PUBLISHER_RECEIPT_TIMEOUT", 60*time.Second),
		ReceiptPollInterval:     getDuration("PUBLISHER_RECEIPT_POLL_INTERVAL", 200*time.Millisecond),
		OwnerWait:               getDuration("PUBLISHER_OWNER_WAIT", 20*time.Second),
		OwnerPoll:               getDuration("PUBLISHER_OWNER_POLL", 2*time.Second),
		ResyncInterval:          getDuration("RESYNC_INTERVAL", 0),
		ResyncPageSize:          getInt("RESYNC_PAGE_SIZE", 500),
		BackoffBase:             getDuration("PUBLISHER_BACKOFF_BASE", 10*time.Millisecond),
		PollJitter:              getFloat("PUBLISHER_POLL_JITTER", 0.1),
		RPCURLs:                 rpcURLs,
		PublisherKeyHex:         os.Getenv("PUBLISHER_EOA_KEY"),
		GrantStoreURL:           os.Getenv("GRANT_STORE_URL"),
		R2URL:                   os.Getenv("R2_URL"),
		R2Token:                 r2Token,
		AWSAccessKeyID:          os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey:      awsSecretAccessKey,
		AWSRegion:               getEnvOrDefault("AWS_REGION", "auto"),
	}
	return cfg
}

// sameEndpoint reports whether two URLs address the same host+path (ignoring a
// trailing slash) — used to reject GRANT_STORE_URL == R2_URL (P3).
func sameEndpoint(a, b string) bool {
	return strings.TrimRight(strings.TrimSpace(a), "/") == strings.TrimRight(strings.TrimSpace(b), "/")
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
	logConfigValue(logger, "PUBLISHER_GAS_LIMIT", int(c.GasLimit))
	weiOrEmpty := func(v *big.Int) string {
		if v == nil {
			return ""
		}
		return v.String()
	}
	logConfigValue(logger, "PUBLISHER_MAX_FEE_PER_GAS", weiOrEmpty(c.MaxFeePerGasWei))
	logConfigValue(logger, "PUBLISHER_MAX_PRIORITY_FEE", weiOrEmpty(c.MaxPriorityFeePerGasWei))
	logConfigValue(logger, "PUBLISHER_RECEIPT_TIMEOUT", c.ReceiptTimeout)
	logConfigValue(logger, "PUBLISHER_OWNER_WAIT", c.OwnerWait)
	logConfigValue(logger, "PUBLISHER_OWNER_POLL", c.OwnerPoll)
	logConfigValue(logger, "RESYNC_INTERVAL", c.ResyncInterval)
	logConfigValue(logger, "RESYNC_PAGE_SIZE", c.ResyncPageSize)
	logConfigValue(logger, "PUBLISHER_RECEIPT_POLL_INTERVAL", c.ReceiptPollInterval)
	logConfigValue(logger, "PUBLISHER_BACKOFF_BASE", c.BackoffBase)
	logConfigValue(logger, "PUBLISHER_POLL_JITTER", fmt.Sprintf("%g", c.PollJitter))
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
	// A slow-to-mine tx must resolve before the queue redelivers it, else it is
	// reprocessed as a duplicate while still in flight (R2-4).
	if c.VisibilityTimeout <= c.ReceiptTimeout {
		return fmt.Errorf("VISIBILITY_TIMEOUT (%s) must exceed PUBLISHER_RECEIPT_TIMEOUT (%s)",
			c.VisibilityTimeout, c.ReceiptTimeout)
	}
	// The owner drain holds a message in-cycle for up to OwnerWait; a group that
	// clears mid-drain then still needs ReceiptTimeout to mine. Both happen
	// under the same lease, so OwnerWait + ReceiptTimeout must stay inside the
	// visibility window or a still-in-flight message is redelivered as a
	// duplicate (FOR-395, plan-2607-06). Negative OwnerWait is nonsensical; zero
	// disables the drain.
	if c.OwnerWait < 0 {
		return fmt.Errorf("PUBLISHER_OWNER_WAIT (%s) must not be negative", c.OwnerWait)
	}
	if c.OwnerPoll < 0 {
		return fmt.Errorf("PUBLISHER_OWNER_POLL (%s) must not be negative", c.OwnerPoll)
	}
	if c.OwnerWait > 0 && c.OwnerWait+c.ReceiptTimeout >= c.VisibilityTimeout {
		return fmt.Errorf(
			"PUBLISHER_OWNER_WAIT (%s) + PUBLISHER_RECEIPT_TIMEOUT (%s) must be less than VISIBILITY_TIMEOUT (%s)",
			c.OwnerWait, c.ReceiptTimeout, c.VisibilityTimeout)
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
	if c.GasLimit == 0 {
		return fmt.Errorf("PUBLISHER_GAS_LIMIT must be greater than zero")
	}
	if c.ReceiptTimeout <= 0 || c.ReceiptPollInterval <= 0 {
		return fmt.Errorf("PUBLISHER_RECEIPT_TIMEOUT and PUBLISHER_RECEIPT_POLL_INTERVAL must be positive")
	}
	if c.GrantStoreURL == "" {
		return fmt.Errorf("GRANT_STORE_URL is required (anonymous public-read grant/genesis bucket domain)")
	}
	if err := validateHTTPSURL(c.GrantStoreURL); err != nil {
		return fmt.Errorf("GRANT_STORE_URL is invalid: %w", err)
	}
	if c.R2URL == "" {
		return fmt.Errorf("R2_URL is required")
	}
	if sameEndpoint(c.GrantStoreURL, c.R2URL) {
		return fmt.Errorf(
			"GRANT_STORE_URL must be the anonymous public bucket domain, distinct from R2_URL (the SigV4 S3-API endpoint); anonymous grant reads against the S3 endpoint return 403")
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
	logConfigValue(logger, name, logredact.StringFingerprint(value))
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
