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
	"github.com/forestrie/arbor/services/pkgs/logredact"
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

	// Delegation seams (coordinator trust root + Custodian issuer proxy)
	TrustRootURL          string
	TrustRootToken        string
	DelegationIssuerURL   string
	DelegationIssuerToken string

	// Univocity trusted authority resolver. When UnivocityAuthorityURL is set,
	// the sealer resolves a log's authoritative root key + chain binding from
	// univocity (GET /api/logs/{logId}/authority, cold-log capable) instead of
	// the legacy trust-root-by-logId path, then verifies the delegation locally.
	UnivocityAuthorityURL string
	UnivocityAPIToken     string

	// Delegated checkpoint keys are ES256 (P-256) only.
	DelegationKeyCurve string

	// DelegationRangePad widens the MMR range requested at delegation issuance
	// beyond the current seal window: the request becomes
	// [mmrStart, mmrEnd + pad] (in MMR node indices). Every range-coverage
	// check downstream (lease cache, on-chain publishCheckpoint, coordinator
	// exact-match against the request) accepts the wider window, so one signed
	// certificate covers every subsequent seal until the log outgrows the pad
	// or the lease TTL expires — issuance leaves the per-append hot path
	// (FOR-386). The pad trades signer round-trips for pre-authorization
	// breadth; the TTL still bounds the delegation in time. 0 disables padding
	// (legacy per-seal windows).
	DelegationRangePad uint64

	// DelegationMaxLeases caps the sealer's per-log delegation lease LRU.
	// With padded ranges (FOR-386) the lease cache is latency-load-bearing:
	// eviction of an active log's lease forces a fresh issuance round-trip on
	// its next seal (~10s+ with a wallet signer). Size for the expected number
	// of concurrently active logs on the lane.
	DelegationMaxLeases int

	// Deprecated migration aliases (fall back when seam URLs/tokens unset).
	CustodianURL      string
	CustodianAppToken string

	// Delegation-in-advance (ADR-0050 / plan-2607-20). When DelegateKeyEpoch
	// is 0 the whole feature is off and the sealer behaves exactly as before
	// (on-demand issuance). When >= 1 the sealer derives standing delegate
	// keys for epochs N and N-1 at boot from a seed source and advertises the
	// current key to the coordinator. No private material is ever at rest:
	// the seed is re-derived each boot from KMS (via the custodian) or, for
	// self-hosted sealers, from a locally-held DELEGATE_SEED.
	SealerID         string
	DelegateKeyEpoch uint32

	// Seed sources (first non-empty wins). DelegateSeedCustodianURL/Token hit
	// the custodian POST /api/delegate-seed (KMS-MAC); they fall back to
	// CustodianURL/CustodianAppToken. DelegateSeedLocal is the self-hosted
	// escape hatch (raw secret, HKDF-mixed per epoch).
	DelegateSeedCustodianURL   string
	DelegateSeedCustodianToken string
	DelegateSeedLocal          []byte

	// CoordinatorRegisterURL is where the sealer POSTs its advertised delegate
	// key (POST /api/sealer/delegate-keys). Best-effort; falls back to
	// TrustRootURL (the coordinator seam). Registration failure never blocks
	// boot — the coordinator can also learn the key at issuance time.
	CoordinatorRegisterURL   string
	CoordinatorRegisterToken string

	// Read-only chain RPC for KS256 ERC-1271 delegation verification (optional).
	ContractRPCURL string

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

	getUint64 := func(key string, defaultVal uint64) uint64 {
		if val := os.Getenv(key); val != "" {
			if parsed, err := strconv.ParseUint(val, 10, 64); err == nil {
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
		Port:                  getEnvOrDefault("PORT", "9090"),
		LogLevel:              getEnvOrDefault("LOG_LEVEL", "info"),
		ShutdownTimeout:       getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		QueueURL:              os.Getenv("QUEUE_URL"),
		QueueToken:            os.Getenv("QUEUE_TOKEN"),
		QueueBatchSize:        getInt("QUEUE_BATCH_SIZE", 31),
		PollIntervalMin:       getDuration("POLL_INTERVAL_MIN", 0),
		PollIntervalMax:       getDuration("POLL_INTERVAL_MAX", 5*time.Second),
		VisibilityTimeout:     getDuration("VISIBILITY_TIMEOUT", 30*time.Second),
		CustodianURL:          os.Getenv("CUSTODIAN_URL"),
		CustodianAppToken:     os.Getenv("CUSTODIAN_APP_TOKEN"),
		TrustRootURL:          os.Getenv("TRUST_ROOT_URL"),
		TrustRootToken:        os.Getenv("TRUST_ROOT_TOKEN"),
		DelegationIssuerURL:   os.Getenv("DELEGATION_ISSUER_URL"),
		DelegationIssuerToken: os.Getenv("DELEGATION_ISSUER_TOKEN"),
		UnivocityAuthorityURL: os.Getenv("UNIVOCITY_AUTHORITY_URL"),
		UnivocityAPIToken:     os.Getenv("UNIVOCITY_API_TOKEN"),
		DelegationKeyCurve:    getEnvOrDefault("DELEGATION_KEY_CURVE", "secp256r1"),
		// Default 65536 MMR nodes (~32k leaves): generous enough that at demo
		// and e2e append rates the lease TTL — not the range — is the binding
		// constraint, i.e. many minutes of cached ephemeral-key reuse.
		DelegationRangePad:  getUint64("DELEGATION_RANGE_PAD", 65536),
		DelegationMaxLeases: getInt("DELEGATION_MAX_LEASES", 1000),
		ContractRPCURL:      os.Getenv("UNIVOCITY_CONTRACT_RPC_URL"),
		R2URL:               os.Getenv("R2_URL"),
		R2Token:             r2Token,
		AWSAccessKeyID:      os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey:  awsSecretAccessKey,
		AWSRegion:           getEnvOrDefault("AWS_REGION", "auto"),

		SealerID:                   getEnvOrDefault("SEALER_ID", "sealer-default"),
		DelegateKeyEpoch:           uint32(getUint64("DELEGATE_KEY_EPOCH", 0)),
		DelegateSeedCustodianURL:   os.Getenv("DELEGATE_SEED_CUSTODIAN_URL"),
		DelegateSeedCustodianToken: os.Getenv("DELEGATE_SEED_CUSTODIAN_TOKEN"),
		DelegateSeedLocal:          []byte(os.Getenv("DELEGATE_SEED")),
		CoordinatorRegisterURL:     os.Getenv("COORDINATOR_REGISTER_URL"),
		CoordinatorRegisterToken:   os.Getenv("COORDINATOR_REGISTER_TOKEN"),
	}

	cfg.applyDelegationSeamFallbacks()
	return cfg
}

func (c *Config) applyDelegationSeamFallbacks() {
	if c.TrustRootURL == "" {
		c.TrustRootURL = c.CustodianURL
	}
	if c.DelegationIssuerURL == "" {
		c.DelegationIssuerURL = c.CustodianURL
	}
	if c.DelegationIssuerToken == "" {
		c.DelegationIssuerToken = c.CustodianAppToken
	}
	// Delegate-seed and coordinator-registration seams reuse the custodian /
	// trust-root plumbing unless overridden explicitly.
	if c.DelegateSeedCustodianURL == "" {
		c.DelegateSeedCustodianURL = c.CustodianURL
	}
	if c.DelegateSeedCustodianToken == "" {
		c.DelegateSeedCustodianToken = c.CustodianAppToken
	}
	if c.CoordinatorRegisterURL == "" {
		c.CoordinatorRegisterURL = c.TrustRootURL
	}
	if c.CoordinatorRegisterToken == "" {
		c.CoordinatorRegisterToken = c.TrustRootToken
	}
}

func (c Config) LogConfig(logger *slog.Logger) {
	logConfigValue(logger, "QUEUE_URL", c.QueueURL)
	logSecretDigest(logger, "QUEUE_TOKEN", c.QueueToken)
	logConfigValue(logger, "QUEUE_BATCH_SIZE", c.QueueBatchSize)
	logConfigValue(logger, "POLL_INTERVAL_MIN", c.PollIntervalMin)
	logConfigValue(logger, "POLL_INTERVAL_MAX", c.PollIntervalMax)
	logConfigValue(logger, "VISIBILITY_TIMEOUT", c.VisibilityTimeout)
	logConfigValue(logger, "TRUST_ROOT_URL", c.TrustRootURL)
	logSecretDigest(logger, "TRUST_ROOT_TOKEN", c.TrustRootToken)
	logConfigValue(logger, "DELEGATION_ISSUER_URL", c.DelegationIssuerURL)
	logSecretDigest(logger, "DELEGATION_ISSUER_TOKEN", c.DelegationIssuerToken)
	logConfigValue(logger, "UNIVOCITY_AUTHORITY_URL", c.UnivocityAuthorityURL)
	logSecretDigest(logger, "UNIVOCITY_API_TOKEN", c.UnivocityAPIToken)
	logConfigValue(logger, "CUSTODIAN_URL", c.CustodianURL)
	logSecretDigest(logger, "CUSTODIAN_APP_TOKEN", c.CustodianAppToken)
	logConfigValue(logger, "SEALER_ID", c.SealerID)
	logConfigValue(logger, "DELEGATE_KEY_EPOCH", int(c.DelegateKeyEpoch))
	logConfigValue(logger, "DELEGATE_SEED_CUSTODIAN_URL", c.DelegateSeedCustodianURL)
	logSecretDigest(logger, "DELEGATE_SEED_CUSTODIAN_TOKEN", c.DelegateSeedCustodianToken)
	logSecretDigest(logger, "DELEGATE_SEED", string(c.DelegateSeedLocal))
	logConfigValue(logger, "COORDINATOR_REGISTER_URL", c.CoordinatorRegisterURL)
	logSecretDigest(logger, "COORDINATOR_REGISTER_TOKEN", c.CoordinatorRegisterToken)
	logConfigValue(logger, "DELEGATION_KEY_CURVE", c.DelegationKeyCurve)
	logConfigValue(logger, "DELEGATION_RANGE_PAD", c.DelegationRangePad)
	logConfigValue(logger, "DELEGATION_MAX_LEASES", c.DelegationMaxLeases)
	logConfigValue(logger, "UNIVOCITY_CONTRACT_RPC_URL", c.ContractRPCURL)
	logConfigValue(logger, "R2_URL", c.R2URL)
	logSecretDigest(logger, "R2_TOKEN", c.R2Token)
	logSecretDigest(logger, "AWS_ACCESS_KEY_ID", c.AWSAccessKeyID)
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

	if c.TrustRootURL == "" {
		return fmt.Errorf("TRUST_ROOT_URL is required (or set CUSTODIAN_URL during migration)")
	}
	if err := validateHTTPSURL(c.TrustRootURL); err != nil {
		return fmt.Errorf("TRUST_ROOT_URL is invalid: %w", err)
	}
	if c.trustRootUsesCoordinator() && strings.TrimSpace(c.TrustRootToken) == "" {
		return fmt.Errorf(
			"TRUST_ROOT_TOKEN is required when TRUST_ROOT_URL differs from CUSTODIAN_URL",
		)
	}
	if c.DelegationIssuerURL == "" {
		return fmt.Errorf("DELEGATION_ISSUER_URL is required (or set CUSTODIAN_URL during migration)")
	}
	if err := validateHTTPSURL(c.DelegationIssuerURL); err != nil {
		return fmt.Errorf("DELEGATION_ISSUER_URL is invalid: %w", err)
	}
	if c.DelegationIssuerToken == "" {
		return fmt.Errorf("DELEGATION_ISSUER_TOKEN is required (or set CUSTODIAN_APP_TOKEN during migration)")
	}
	if curve, err := delegationcert.ParseCurve(c.DelegationKeyCurve); err != nil {
		return fmt.Errorf("DELEGATION_KEY_CURVE is invalid: %w", err)
	} else if curve != delegationcert.Secp256r1 {
		return fmt.Errorf("DELEGATION_KEY_CURVE must be secp256r1 (ES256)")
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

func (c Config) trustRootUsesCoordinator() bool {
	trust := strings.TrimRight(strings.TrimSpace(c.TrustRootURL), "/")
	cust := strings.TrimRight(strings.TrimSpace(c.CustodianURL), "/")
	return trust != "" && trust != cust
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
