package sealer

import (
	"testing"

	"github.com/forestrie/go-merklelog/massifs"
	"github.com/stretchr/testify/require"
)

// FOR-410 / ADR-0056: the checkpoint proof base must be the massif's entry
// boundary on EVERY seal — replacing sth(a->b) with a re-seal at size c
// yields sth(a->c), never sth(b->c).
func TestDecideSealResealKeepsBoundaryBase(t *testing.T) {
	// The live drift shape that motivated FOR-410: massif 0 previously
	// sealed at 159, re-sealing at 206. The bug produced base 159; the
	// invariant requires base 0.
	d := decideSeal(0, 206, 159, true)
	require.False(t, d.skip)
	require.Equal(t, uint64(0), d.base, "re-seal base must stay at the entry boundary, not the previous seal")

	// A non-head massif (fresh, no checkpoint yet) seals from its boundary.
	boundary := massifs.MassifFirstLeaf(14, 3)
	d = decideSeal(boundary, boundary+100, 0, false)
	require.False(t, d.skip)
	require.Equal(t, boundary, d.base)
}

func TestDecideSealSkipsWhenNoAdvance(t *testing.T) {
	// Exactly at the last sealed size: nothing to re-seal.
	d := decideSeal(0, 206, 206, true)
	require.True(t, d.skip)
	// Behind the last sealed size (concurrent writer raced ahead): skip.
	d = decideSeal(0, 200, 206, true)
	require.True(t, d.skip)
	// Empty massif: skip.
	d = decideSeal(massifs.MassifFirstLeaf(14, 1), 0, 0, false)
	require.True(t, d.skip)
}

// A drifted legacy log self-heals: even when the head checkpoint's base has
// drifted (lastSealedSize is an intermediate), the next seal's base is the
// structural boundary, not anything derived from the drifted checkpoint.
func TestDecideSealSelfHealsDriftedBase(t *testing.T) {
	boundary := massifs.MassifFirstLeaf(14, 2)
	drifted := boundary + 500 // legacy checkpoint sealed at an intermediate
	d := decideSeal(boundary, drifted+50, drifted, true)
	require.False(t, d.skip)
	require.Equal(t, boundary, d.base)
}

// The retained chain is contiguous by construction: massif boundaries are
// strictly increasing and each massif's entry boundary is where the
// previous massif's final seal (its complete RangeCount) ends.
func TestMassifBoundariesStrictlyIncrease(t *testing.T) {
	for _, height := range []uint8{2, 8, 14} {
		prev := massifs.MassifFirstLeaf(height, 0)
		require.Equal(t, uint64(0), prev)
		for mi := uint32(1); mi <= 4; mi++ {
			b := massifs.MassifFirstLeaf(height, mi)
			require.Greater(t, b, prev, "height %d massif %d", height, mi)
			prev = b
		}
	}
}
