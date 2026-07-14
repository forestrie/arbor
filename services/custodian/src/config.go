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
	AppToken          string // Normal: key ensure, list keys, public key, custody key signing
	BootstrapAppToken string // Privileged: key destruction (POST .../delete)

	// GCP: custody signer SA (IAM grants per key) and custody key ring for key creation.
	CustodySignerSAEmail string
	// CustodianRuntimeSAEmail is the GCP SA used by this process (ADC). When set,
	// EnsureKeyForOwner grants it signerVerifier and publicKeyViewer on each
	// custody key so SignAsymmetric and GetPublicKey succeed for that identity.
	CustodianRuntimeSAEmail string
	CustodyKeyRingID        string // Full key ring ID (projects/.../locations/.../keyRings/...)
	GCPProjectID            string // Project ID (for KMS API)
	GCPLocation             string // Location (e.g. europe-west2)

	// LogIDCacheSize caps in-memory log id → key id LRU.
	// Default 1024 when LOG_ID_CACHE_SIZE is unset; set env to "0" to disable.
	LogIDCacheSize int

	// DelegationCoordinatorURL is the base URL for the delegation-coordinator Worker
	// (e.g. https://coordinator-dev.forestrie.dev). When set, wallet-managed logs and
	// local-key misses proxy POST /api/delegations to the coordinator.
	DelegationCoordinatorURL string
	// DelegationCoordinatorToken is the Bearer token for coordinator management/issue APIs.
	// Defaults to APP_TOKEN when unset.
	DelegationCoordinatorToken string

	// DelegateSeedMacKey is the full KMS CryptoKey resource name of the
	// dedicated HMAC-SHA256 MAC key used to derive sealer delegate-key seeds
	// (ADR-0050 / plan-2607-20 phase A). Empty disables POST /api/delegate-seed.
	DelegateSeedMacKey string
	// RegistrarVoucherKey is the full KMS CryptoKey resource name of the
	// dedicated EC P-256 signing key the custodian uses to sign delegate-key
	// vouchers (ADR-0050 §"Trust model" / plan-2607-20 phase G). Distinct from
	// DelegateSeedMacKey (a MAC key cannot make public-verifiable signatures)
	// and from the per-log custody keys. Empty disables voucher signing.
	RegistrarVoucherKey string
	// DelegateSeedSealers is the allowlist of sealerId values permitted to
	// derive seeds (comma-separated env DELEGATE_SEED_SEALERS).
	DelegateSeedSealers []string
}

// delegateSeedSealerAllowed reports whether sealerId is in the allowlist.
func (c Config) delegateSeedSealerAllowed(sealerID string) bool {
	for _, s := range c.DelegateSeedSealers {
		if s == sealerID {
			return true
		}
	}
	return false
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
		CustodianRuntimeSAEmail: strings.TrimSpace(os.Getenv("CUSTODIAN_RUNTIME_SA_EMAIL")),
		CustodyKeyRingID:        os.Getenv("CUSTODY_KEY_RING_ID"),
		GCPProjectID:            os.Getenv("GCP_PROJECT_ID"),
		GCPLocation:             getEnvOrDefault("GCP_LOCATION", "europe-west2"),
		LogIDCacheSize:          logCache,
		DelegationCoordinatorURL: strings.TrimRight(
			strings.TrimSpace(os.Getenv("DELEGATION_COORDINATOR_URL")),
			"/",
		),
		DelegationCoordinatorToken: strings.TrimSpace(os.Getenv("DELEGATION_COORDINATOR_TOKEN")),
		DelegateSeedMacKey:         strings.TrimSpace(os.Getenv("DELEGATE_SEED_MAC_KEY")),
		RegistrarVoucherKey:        strings.TrimSpace(os.Getenv("REGISTRAR_VOUCHER_KEY")),
		DelegateSeedSealers:        splitNonEmpty(os.Getenv("DELEGATE_SEED_SEALERS")),
	}
}

// splitNonEmpty splits a comma-separated env value, trimming blanks.
func splitNonEmpty(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// LogConfig logs non-secret configuration values for observability.
func (c Config) LogConfig(logger *slog.Logger) {
	logger.Warn("config value", "name", "PORT", "value", c.Port)
	logger.Warn("config value", "name", "LOG_LEVEL", "value", c.LogLevel)
	logger.Warn("config value", "name", "SHUTDOWN_TIMEOUT", "value", c.ShutdownTimeout.String())
	logger.Warn("config value", "name", "APP_TOKEN", "value", secretDigest(c.AppToken))
	logger.Warn("config value", "name", "BOOTSTRAP_APP_TOKEN", "value", secretDigest(c.BootstrapAppToken))
	logger.Warn("config value", "name", "CUSTODY_SIGNER_SA_EMAIL", "value", c.CustodySignerSAEmail)
	logger.Warn("config value", "name", "CUSTODIAN_RUNTIME_SA_EMAIL", "value", c.CustodianRuntimeSAEmail)
	logger.Warn("config value", "name", "CUSTODY_KEY_RING_ID", "value", c.CustodyKeyRingID)
	logger.Warn("config value", "name", "GCP_PROJECT_ID", "value", c.GCPProjectID)
	logger.Warn("config value", "name", "GCP_LOCATION", "value", c.GCPLocation)
	logger.Warn("config value", "name", "LOG_ID_CACHE_SIZE", "value", c.LogIDCacheSize)
	logger.Warn("config value", "name", "DELEGATION_COORDINATOR_URL", "value", c.DelegationCoordinatorURL)
	logger.Warn("config value", "name", "DELEGATION_COORDINATOR_TOKEN", "value", secretDigest(c.DelegationCoordinatorToken))
	logger.Warn("config value", "name", "DELEGATE_SEED_MAC_KEY", "value", c.DelegateSeedMacKey)
	logger.Warn("config value", "name", "REGISTRAR_VOUCHER_KEY", "value", c.RegistrarVoucherKey)
	logger.Warn("config value", "name", "DELEGATE_SEED_SEALERS", "value", strings.Join(c.DelegateSeedSealers, ","))
}

func secretDigest(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
