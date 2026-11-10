package sealer

import (
	"os"
	"strings"
	"testing"
)

// validConfig is a configuration Validate accepts, with the local seed
// source so no custodian is involved.
func validConfig() Config {
	return Config{
		QueueURL:                 "https://queue.example/pull",
		QueueToken:               "qt",
		QueueBatchSize:           1,
		DelegationIssuerURL:      "http://custodian:9092",
		DelegationIssuerToken:    "issuer",
		UnivocityAuthorityURL:    "http://univocity:9091",
		DelegationKeyCurve:       "secp256r1",
		DelegateKeyEpochRaw:      "1",
		DelegateSeedLocal:        []byte("seed"),
		CoordinatorRegisterURL:   "https://coordinator.example.com",
		CoordinatorRegisterToken: "coord-token",
		R2URL:                    "https://r2.example",
		AWSAccessKeyID:           "key",
		AWSSecretAccessKey:       "secret",
	}
}

// The sealer takes root keys only from univocity (devdocs ADR-0075
// decision 5), and registers its delegate keys and pages active delegations
// at the coordinator, so it refuses to start without either, whatever its
// seed source.
func TestConfigValidate_requiresUnivocityAuthorityAndCoordinator(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	cases := map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"no authority url":  {func(c *Config) { c.UnivocityAuthorityURL = "" }, "UNIVOCITY_AUTHORITY_URL"},
		"bad authority url": {func(c *Config) { c.UnivocityAuthorityURL = "univocity:9091" }, "UNIVOCITY_AUTHORITY_URL"},
		"no register url":   {func(c *Config) { c.CoordinatorRegisterURL = "" }, "COORDINATOR_REGISTER_URL"},
		"bad register url":  {func(c *Config) { c.CoordinatorRegisterURL = "coordinator" }, "COORDINATOR_REGISTER_URL"},
		"no register token": {func(c *Config) { c.CoordinatorRegisterToken = " " }, "COORDINATOR_REGISTER_TOKEN"},
	}
	for name, tc := range cases {
		for _, custodianSeed := range []bool{false, true} {
			cfg := validConfig()
			if custodianSeed {
				cfg.DelegateSeedLocal = nil
				cfg.DelegateSeedCustodianURL = "http://custodian:9092"
				cfg.DelegateSeedCustodianToken = "app"
			}
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("%s (custodian seed %v): expected an error", name, custodianSeed)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s (custodian seed %v): error should name %s, got: %v",
					name, custodianSeed, tc.want, err)
			}
		}
	}
}

// TRUST_ROOT_URL and TRUST_ROOT_TOKEN are gone: the coordinator settings no
// longer default from them, so a lane that sets only those fails to start
// rather than registering wherever they point.
func TestLoadConfig_coordinatorRegisterHasNoTrustRootFallback(t *testing.T) {
	t.Setenv("TRUST_ROOT_URL", "https://coordinator.example.com")
	t.Setenv("TRUST_ROOT_TOKEN", "coord-token")
	t.Setenv("CUSTODIAN_URL", "http://custodian:9092")
	t.Setenv("COORDINATOR_REGISTER_URL", "")
	t.Setenv("COORDINATOR_REGISTER_TOKEN", "")
	cfg := LoadConfig()
	if cfg.CoordinatorRegisterURL != "" || cfg.CoordinatorRegisterToken != "" {
		t.Fatalf("coordinator register defaulted: url=%q token set=%v",
			cfg.CoordinatorRegisterURL, cfg.CoordinatorRegisterToken != "")
	}
}

// FOR-390: DELEGATE_KEY_EPOCH has no in-code default, and since on-demand
// delegation was removed (devdocs plan-2609-12 slice 10) it must be >= 1:
// unset, 0 and unparseable all refuse to start.
func TestConfigValidate_requiresDelegateKeyEpoch(t *testing.T) {
	base := func() Config {
		cfg := validConfig()
		cfg.DelegateKeyEpochRaw = ""
		return cfg
	}

	cfg := base()
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when DELEGATE_KEY_EPOCH is unset")
	} else if !strings.Contains(err.Error(), "DELEGATE_KEY_EPOCH") {
		t.Fatalf("error should name the variable, got: %v", err)
	}

	cfg = base()
	cfg.DelegateKeyEpochRaw = "not-a-number"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when DELEGATE_KEY_EPOCH is unparseable")
	}

	cfg = base()
	cfg.DelegateKeyEpochRaw = "0"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when DELEGATE_KEY_EPOCH is 0")
	} else if !strings.Contains(err.Error(), "on-demand delegation was removed") {
		t.Fatalf("error should say why 0 is refused, got: %v", err)
	}

	for _, raw := range []string{"1", "7"} {
		cfg = base()
		cfg.DelegateKeyEpochRaw = raw
		if err := cfg.Validate(); err != nil {
			t.Fatalf("DELEGATE_KEY_EPOCH=%s should be valid, got: %v", raw, err)
		}
	}
}

// LoadConfig must not invent a value: an absent variable stays absent so
// Validate can reject it.
func TestLoadConfig_delegateKeyEpochNotDefaulted(t *testing.T) {
	t.Setenv("DELEGATE_KEY_EPOCH", "")
	os.Unsetenv("DELEGATE_KEY_EPOCH")
	if got := LoadConfig().DelegateKeyEpochRaw; got != "" {
		t.Fatalf("DelegateKeyEpochRaw=%q want empty when unset", got)
	}

	t.Setenv("DELEGATE_KEY_EPOCH", "0")
	cfg := LoadConfig()
	if cfg.DelegateKeyEpochRaw != "0" || cfg.DelegateKeyEpoch != 0 {
		t.Fatalf("explicit 0 not carried through: raw=%q epoch=%d", cfg.DelegateKeyEpochRaw, cfg.DelegateKeyEpoch)
	}

	t.Setenv("DELEGATE_KEY_EPOCH", "2")
	if got := LoadConfig().DelegateKeyEpoch; got != 2 {
		t.Fatalf("DelegateKeyEpoch=%d want 2", got)
	}
}

// Epoch >= 1 needs a seed source; without one the sealer could never install
// keys, so it refuses to start rather than retry forever.
func TestConfigValidate_requiresDelegateSeedSource(t *testing.T) {
	cfg := validConfig()
	cfg.DelegateSeedLocal = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error with no delegate seed source")
	}
	cfg.DelegateSeedCustodianURL = "http://custodian:9092"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("custodian seed source should be valid, got: %v", err)
	}
}

// Lanes set only CUSTODIAN_URL (arbor-flux Taskfile, Doppler sealer config),
// not DELEGATE_SEED_CUSTODIAN_URL. LoadConfig must fall back to it so the
// seed-source check in Validate passes, or the sealer refuses to start.
func TestLoadConfig_seedSourceFallsBackToCustodianURL(t *testing.T) {
	t.Setenv("DELEGATE_SEED_CUSTODIAN_URL", "")
	t.Setenv("DELEGATE_SEED", "")
	t.Setenv("CUSTODIAN_URL", "http://custodian:9092")
	if got := LoadConfig().DelegateSeedCustodianURL; got != "http://custodian:9092" {
		t.Fatalf("DelegateSeedCustodianURL=%q want the CUSTODIAN_URL fallback", got)
	}

	t.Setenv("DELEGATE_SEED_CUSTODIAN_URL", "http://seed:9092")
	if got := LoadConfig().DelegateSeedCustodianURL; got != "http://seed:9092" {
		t.Fatalf("DelegateSeedCustodianURL=%q want the explicit value", got)
	}
}
