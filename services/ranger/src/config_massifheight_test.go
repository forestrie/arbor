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
