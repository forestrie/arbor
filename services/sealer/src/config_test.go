package sealer

import "testing"

func TestConfig_trustRootUsesCoordinator(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		cfg    Config
		want   bool
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
		QueueToken:              "qt",
		QueueBatchSize:          1,
		TrustRootURL:            "https://coordinator.example.com",
		CustodianURL:            "http://custodian:9092",
		DelegationIssuerURL:     "http://custodian:9092",
		DelegationIssuerToken:   "issuer",
		DelegationKeyCurve:      "secp256r1",
		R2URL:                   "https://r2.example",
		AWSAccessKeyID:          "key",
		AWSSecretAccessKey:      "secret",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when TRUST_ROOT_TOKEN missing for coordinator URL")
	}
	cfg.TrustRootToken = "coord-token"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}
}
