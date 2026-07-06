package publisher

import (
	"testing"
	"time"
)

func TestParseRPCURLs(t *testing.T) {
	m, err := parseRPCURLs(`{"84532":"https://sepolia.base.org","31337":"http://127.0.0.1:8545"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m[84532] != "https://sepolia.base.org" || m[31337] != "http://127.0.0.1:8545" {
		t.Errorf("unexpected map: %v", m)
	}

	for _, bad := range []string{"", "not json", "{}", `{"abc":"http://x"}`, `{"1":""}`} {
		if _, err := parseRPCURLs(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func baseValidCLIConfig() Config {
	return Config{
		RPCURLs:             map[uint64]string{84532: "https://sepolia.base.org"},
		PublisherKeyHex:     anvilKey0,
		GrantStoreURL:       "https://pub.example.com",
		R2URL:               "https://r2.example.com",
		AWSAccessKeyID:      "akid",
		AWSSecretAccessKey:  "secret",
		AWSRegion:           "auto",
		GasLimit:            3_000_000,
		ReceiptTimeout:      60 * time.Second,
		ReceiptPollInterval: 200 * time.Millisecond,
	}
}

func TestValidateCLI(t *testing.T) {
	if err := baseValidCLIConfig().ValidateCLI(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := map[string]func(*Config){
		"no chains":       func(c *Config) { c.RPCURLs = nil },
		"no key":          func(c *Config) { c.PublisherKeyHex = "" },
		"bad key":         func(c *Config) { c.PublisherKeyHex = "xyz" },
		"no grant url":    func(c *Config) { c.GrantStoreURL = "" },
		"grant url == r2": func(c *Config) { c.GrantStoreURL = c.R2URL },
		"no r2":           func(c *Config) { c.R2URL = "" },
		"no akid":         func(c *Config) { c.AWSAccessKeyID = "" },
		"no secret":       func(c *Config) { c.AWSSecretAccessKey = "" },
		"zero gas":        func(c *Config) { c.GasLimit = 0 },
		"no receipt":      func(c *Config) { c.ReceiptTimeout = 0 },
	}
	for name, mutate := range cases {
		cfg := baseValidCLIConfig()
		mutate(&cfg)
		if err := cfg.ValidateCLI(); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestValidateDaemonRequiresQueue(t *testing.T) {
	cfg := baseValidCLIConfig()
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected daemon validate to require QUEUE_URL")
	}
	cfg.QueueURL = "https://api.cloudflare.com/x"
	cfg.QueueToken = "tok"
	cfg.QueueBatchSize = 31
	if err := cfg.Validate(); err != nil {
		t.Errorf("daemon config rejected: %v", err)
	}
}
