package sealer

import (
	"os"
	"strings"
	"testing"
)

func TestConfig_trustRootUsesCoordinator(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{
			name: "different hosts",
			cfg: Config{
				TrustRootURL: "https://coordinator.example.com",
				CustodianURL: "http://custodian:9092",
			},
			want: true,
		},
		{
			name: "same url",
			cfg: Config{
				TrustRootURL: "http://custodian:9092",
				CustodianURL: "http://custodian:9092",
			},
			want: false,
		},
		{
			name: "fallback alias",
			cfg: Config{
				TrustRootURL: "http://custodian:9092/",
				CustodianURL: "http://custodian:9092",
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.trustRootUsesCoordinator(); got != tc.want {
				t.Fatalf("trustRootUsesCoordinator()=%v want %v", got, tc.want)
			}
		})
	}
}

func TestConfigValidate_requiresTrustRootTokenForCoordinator(t *testing.T) {
	cfg := Config{
		QueueURL:              "https://queue.example/pull",
		QueueToken:            "qt",
		QueueBatchSize:        1,
		TrustRootURL:          "https://coordinator.example.com",
		CustodianURL:          "http://custodian:9092",
		DelegationIssuerURL:   "http://custodian:9092",
		DelegationIssuerToken: "issuer",
		DelegationKeyCurve:    "secp256r1",
		DelegateKeyEpochRaw:   "1",
		DelegateSeedLocal:     []byte("seed"),
		R2URL:                 "https://r2.example",
		AWSAccessKeyID:        "key",
		AWSSecretAccessKey:    "secret",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when TRUST_ROOT_TOKEN missing for coordinator URL")
	}
	cfg.TrustRootToken = "coord-token"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}
}

// FOR-390: DELEGATE_KEY_EPOCH has no in-code default, and since on-demand
// delegation was removed (devdocs plan-2609-12 slice 10) it must be >= 1:
// unset, 0 and unparseable all refuse to start.
func TestConfigValidate_requiresDelegateKeyEpoch(t *testing.T) {
	base := func() Config {
		return Config{
			QueueURL:              "https://queue.example/pull",
			QueueToken:            "qt",
			QueueBatchSize:        1,
			TrustRootURL:          "http://custodian:9092",
			CustodianURL:          "http://custodian:9092",
			DelegationIssuerURL:   "http://custodian:9092",
			DelegationIssuerToken: "issuer",
			DelegationKeyCurve:    "secp256r1",
			R2URL:                 "https://r2.example",
			AWSAccessKeyID:        "key",
			AWSSecretAccessKey:    "secret",
			DelegateSeedLocal:     []byte("seed"),
		}
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
	cfg := Config{
		QueueURL:              "https://queue.example/pull",
		QueueToken:            "qt",
		QueueBatchSize:        1,
		TrustRootURL:          "http://custodian:9092",
		CustodianURL:          "http://custodian:9092",
		DelegationIssuerURL:   "http://custodian:9092",
		DelegationIssuerToken: "issuer",
		DelegationKeyCurve:    "secp256r1",
		DelegateKeyEpochRaw:   "1",
		R2URL:                 "https://r2.example",
		AWSAccessKeyID:        "key",
		AWSSecretAccessKey:    "secret",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error with no delegate seed source")
	}
	cfg.DelegateSeedCustodianURL = "http://custodian:9092"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("custodian seed source should be valid, got: %v", err)
	}
}
