package sealer

// Integration coverage for sealPlanForMassif (R5, plan-2607-09): real
// in-memory massifs exercise the composed FOR-410 behaviours — boundary
// base stability across re-seals, rollover contiguity, R1 cross-massif
// validation (positive and refusal), and the R4 header-forgery guard.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/stretchr/testify/require"
)

// memSealStore is a minimal in-memory ObjectReaderWriter (pattern:
// go-merklelog massifs test memStore).
type memSealStore struct {
	massifs    map[uint32][]byte
	checkpoint map[uint32][]byte
}

func newMemSealStore() *memSealStore {
	return &memSealStore{
		massifs:    map[uint32][]byte{},
		checkpoint: map[uint32][]byte{},
	}
}

func headOf(m map[uint32][]byte) (uint32, error) {
	var max uint32
	var ok bool
	for k := range m {
		if !ok || k > max {
			max = k
			ok = true
		}
	}
	if !ok {
		return 0, storage.ErrLogEmpty
	}
	return max, nil
}

func (m *memSealStore) HeadIndex(ctx context.Context, otype storage.ObjectType) (uint32, error) {
	_ = ctx
	switch otype {
	case storage.ObjectMassifData:
		return headOf(m.massifs)
	case storage.ObjectCheckpoint:
		return headOf(m.checkpoint)
	default:
		return 0, fmt.Errorf("unsupported object type: %v", otype)
	}
}

func (m *memSealStore) MassifData(massifIndex uint32) ([]byte, bool, error) {
	b, ok := m.massifs[massifIndex]
	if !ok {
		return nil, false, storage.ErrDoesNotExist
	}
	return b, true, nil
}

func (m *memSealStore) CheckpointData(massifIndex uint32) ([]byte, bool, error) {
	b, ok := m.checkpoint[massifIndex]
	if !ok {
		return nil, false, storage.ErrDoesNotExist
	}
	return b, true, nil
}

func (m *memSealStore) MassifReadN(ctx context.Context, massifIndex uint32, n int) ([]byte, error) {
	_ = ctx
	b, ok := m.massifs[massifIndex]
	if !ok {
		return nil, storage.ErrDoesNotExist
	}
	if n == -1 || n >= len(b) {
		return b, nil
	}
	return b[:n], nil
}

func (m *memSealStore) CheckpointRead(ctx context.Context, massifIndex uint32) ([]byte, error) {
	_ = ctx
	b, ok := m.checkpoint[massifIndex]
	if !ok {
		return nil, storage.ErrDoesNotExist
	}
	return b, nil
}

func (m *memSealStore) Put(ctx context.Context, massifIndex uint32, ty storage.ObjectType, data []byte, failIfExists bool) error {
	_ = ctx
	_ = failIfExists
	switch ty {
	case storage.ObjectMassifData:
		m.massifs[massifIndex] = append([]byte(nil), data...)
	case storage.ObjectCheckpoint:
		m.checkpoint[massifIndex] = append([]byte(nil), data...)
	default:
		return fmt.Errorf("unsupported object type: %v", ty)
	}
	return nil
}

const testHeight uint8 = 2 // two leaves per massif — rollovers are cheap

// appendLeaves grows the log by n deterministic leaves, rolling massifs as
// they fill (mirrors ranger committer).
func appendLeaves(t *testing.T, store *memSealStore, n int) {
	t.Helper()
	ctx := context.Background()
	mc, err := massifs.GetAppendContext(ctx, store, 0, testHeight)
	require.NoError(t, err)
	for i := 0; i < n; i++ {
		leaf := make([]byte, 8)
		binary.BigEndian.PutUint64(leaf, uint64(i))
		sum := sha256.Sum256(leaf)
		_, err := mc.AddIndexedEntry(sum[:])
		if err == nil {
			continue
		}
		require.ErrorIs(t, err, massifs.ErrMassifFull)
		require.NoError(t, massifs.CommitContext(ctx, store, &mc))
		mc, err = massifs.GetAppendContext(ctx, store, 0, testHeight)
		require.NoError(t, err)
		_, err = mc.AddIndexedEntry(sum[:])
		require.NoError(t, err)
	}
	require.NoError(t, massifs.CommitContext(ctx, store, &mc))
}

func mustContext(t *testing.T, store *memSealStore, mi uint32) massifs.MassifContext {
	t.Helper()
	mc, err := massifs.GetMassifContext(context.Background(), store, mi)
	require.NoError(t, err)
	return mc
}

func TestSealPlanResealKeepsBoundaryBaseOnRealMassif(t *testing.T) {
	store := newMemSealStore()
	appendLeaves(t, store, 1)

	mc := mustContext(t, store, 0)
	plan, err := sealPlanForMassif(&mc, testHeight, 0, 0, false, nil)
	require.NoError(t, err)
	require.False(t, plan.skip)
	require.Equal(t, uint64(0), plan.proof.TreeSize1)
	firstSealSize := plan.curSize

	// Grow and re-seal: the base must remain the entry boundary (sth(0->c)),
	// never the previous seal (the FOR-410 drift).
	appendLeaves(t, store, 1)
	mc = mustContext(t, store, 0)
	plan, err = sealPlanForMassif(&mc, testHeight, 0, firstSealSize, true, nil)
	require.NoError(t, err)
	require.False(t, plan.skip)
	require.Equal(t, uint64(0), plan.proof.TreeSize1)
	require.Greater(t, plan.curSize, firstSealSize)

	// No advance: skip.
	plan, err = sealPlanForMassif(&mc, testHeight, 0, plan.curSize, true, nil)
	require.NoError(t, err)
	require.True(t, plan.skip)
}

func TestSealPlanRolloverCarriedCrossValidation(t *testing.T) {
	store := newMemSealStore()
	appendLeaves(t, store, 3) // massif 0 full (2 leaves) + massif 1 (1 leaf)

	mc0 := mustContext(t, store, 0)
	plan0, err := sealPlanForMassif(&mc0, testHeight, 0, 0, false, nil)
	require.NoError(t, err)
	require.False(t, plan0.skip)

	boundary1 := massifs.MassifFirstLeaf(testHeight, 1)
	// Contiguity: massif 0's final seal ends exactly where massif 1 begins.
	require.Equal(t, boundary1, plan0.curSize)

	carried := &massifCarry{size: plan0.curSize, peaks: plan0.newPeaks}
	mc1 := mustContext(t, store, 1)
	plan1, err := sealPlanForMassif(&mc1, testHeight, 1, 0, false, carried)
	require.NoError(t, err)
	require.False(t, plan1.skip)
	require.Equal(t, boundary1, plan1.proof.TreeSize1)
}

func TestSealPlanCarriedMismatchRefusesToSeal(t *testing.T) {
	store := newMemSealStore()
	appendLeaves(t, store, 3)

	mc0 := mustContext(t, store, 0)
	plan0, err := sealPlanForMassif(&mc0, testHeight, 0, 0, false, nil)
	require.NoError(t, err)

	// Tamper the carried accumulator (equivalently: massif 1's ancestor
	// peak stack disagrees with massif 0's node data).
	carried := &massifCarry{size: plan0.curSize, peaks: plan0.newPeaks}
	carried.peaks[0] = append([]byte(nil), carried.peaks[0]...)
	carried.peaks[0][0] ^= 0xff

	mc1 := mustContext(t, store, 1)
	_, err = sealPlanForMassif(&mc1, testHeight, 1, 0, false, carried)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cross-massif validation failed")
}

func TestSealPlanPeakStackCorruptionRefusesToSeal(t *testing.T) {
	store := newMemSealStore()
	appendLeaves(t, store, 3)

	mc0 := mustContext(t, store, 0)
	plan0, err := sealPlanForMassif(&mc0, testHeight, 0, 0, false, nil)
	require.NoError(t, err)
	carried := &massifCarry{size: plan0.curSize, peaks: plan0.newPeaks}

	// Corrupt massif 1's ancestor peak stack in the BLOB and re-read: the
	// rehydrated boundary peaks then disagree with the carried accumulator.
	blob := store.massifs[1]
	off := int(massifs.PeakStackStart(testHeight))
	require.Less(t, off, len(blob), "peak stack offset within blob")
	blob[off] ^= 0xff

	mc1 := mustContext(t, store, 1)
	_, err = sealPlanForMassif(&mc1, testHeight, 1, 0, false, carried)
	require.Error(t, err)
}

func TestSealPlanHeaderForgeryRefused(t *testing.T) {
	store := newMemSealStore()
	appendLeaves(t, store, 3)

	mc1 := mustContext(t, store, 1)
	mc1.Start.FirstIndex++ // forged header
	_, err := sealPlanForMassif(&mc1, testHeight, 1, 0, false, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "boundary invariant violated")
}
