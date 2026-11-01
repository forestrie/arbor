package ranger

import (
	"testing"

	"github.com/forestrie/go-merklelog/massifs"
)

// TestConfigMassifHeightIsOneBased pins that ranger's MASSIF_HEIGHT is the
// one-based height go-merklelog uses: a massif holds 2^(h-1) leaves. canopy's
// SequencingQueue and canopy-api derive massif indices from the leaf index on
// that basis, so the known-answer rows here match the table in go-merklelog
// massifs/massifindex_test.go and canopy @forestrie/merklelog.
func TestConfigMassifHeightIsOneBased(t *testing.T) {
	t.Setenv("MASSIF_HEIGHT", "")
	cfg := LoadConfig()
	if cfg.MassifHeight != 14 {
		t.Fatalf("default MassifHeight = %d, want 14", cfg.MassifHeight)
	}

	for _, tc := range []struct{ leafIndex, massifIndex uint64 }{
		{0, 0}, {8191, 0}, {8192, 1}, {16383, 1}, {16384, 2},
	} {
		if got := massifs.MassifIndexFromLeafIndex(cfg.MassifHeight, tc.leafIndex); got != tc.massifIndex {
			t.Errorf("h=%d leaf %d -> massif %d, want %d",
				cfg.MassifHeight, tc.leafIndex, got, tc.massifIndex)
		}
	}
}

// TestValidateRejectsMassifHeightOutOfRange: the committer writes massifs at
// MassifHeight and the consumer acks with the same value, so there is no
// fallback default downstream. A zero or oversize height must stop startup.
func TestValidateRejectsMassifHeightOutOfRange(t *testing.T) {
	valid := Config{
		QueueURL:           "https://queue.test",
		QueueToken:         "token",
		QueueBatchSize:     1,
		R2URL:              "https://r2.test/bucket",
		AWSAccessKeyID:     "AKIA_TEST",
		AWSSecretAccessKey: "secret",
		WorkerCIDR:         "10.0.0.0/24",
		PodIP:              "10.0.0.1",
	}
	for _, h := range []uint8{1, 14, 64} {
		cfg := valid
		cfg.MassifHeight = h
		if err := cfg.Validate(); err != nil {
			t.Errorf("MassifHeight=%d: unexpected error %v", h, err)
		}
	}
	for _, h := range []uint8{0, 65} {
		cfg := valid
		cfg.MassifHeight = h
		if err := cfg.Validate(); err == nil {
			t.Errorf("MassifHeight=%d: Validate accepted it", h)
		}
	}
}
