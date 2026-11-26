package committer

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog/merklelogtest"
	"github.com/forestrie/arbor/services/ranger/consumer/ingress"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/forestrie/go-merklelog/urkle"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestRollForwardInMemoryMatchesReread: at a mid-batch rollover the
// committer rolls the context it has just committed forward in memory
// rather than re-reading the head massif. With no other writer the two must
// give the same next massif: start header, bytes and peak stack. Four
// rollovers from an empty log cover the first massif, created in memory,
// and ancestor peak stacks of one and two peaks.
func TestRollForwardInMemoryMatchesReread(t *testing.T) {
	ctx := context.Background()
	client := merklelogtest.NewMemClient()
	const massifHeight = 3
	logID := uuid.New()
	store := openLogStore(t, client, logID, massifHeight)

	mc, err := massifs.GetAppendContext(ctx, store, 1, massifHeight)
	require.NoError(t, err)
	require.True(t, mc.Creating)

	idTimestamp := uint64(1) << 40
	for massifIndex := uint32(0); massifIndex < 4; massifIndex++ {
		for {
			idTimestamp++
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], idTimestamp)
			content := sha256.Sum256(b[:])
			_, err := mc.AddIndexedEntry(leafHash(mc.RangeCount(), idTimestamp, content[:]))
			if errors.Is(err, massifs.ErrMassifFull) {
				break
			}
			require.NoError(t, err)
			require.NoError(t, mc.IndexLeaf(idTimestamp, content[:]))
			mc.SetLastIDTimestamp(idTimestamp)
		}
		require.NoError(t, massifs.CommitContext(ctx, store, &mc))

		rolled := mc
		require.NoError(t, massifs.InitAppendContext(ctx, store, &rolled))

		// A fresh store, so the re-read comes from storage, not a cache.
		reread, err := massifs.GetAppendContext(ctx,
			openLogStore(t, client, logID, massifHeight), 1, massifHeight)
		require.NoError(t, err)

		msg := fmt.Sprintf("rolling massif %d forward", massifIndex)
		require.True(t, rolled.Creating, msg)
		require.True(t, reread.Creating, msg)
		require.Equal(t, massifIndex+1, rolled.Start.MassifIndex, msg)
		require.Equal(t, reread.Start, rolled.Start, msg)
		require.Equal(t, reread.Data, rolled.Data, msg)
		require.Equal(t, reread.PeakStackMap, rolled.PeakStackMap, msg)

		mc = rolled
	}
}

// nodeSlice is a minimal mmr.NodeAppender over a slice.
type nodeSlice [][]byte

func (s *nodeSlice) Get(i uint64) ([]byte, error) {
	if i >= uint64(len(*s)) {
		return nil, fmt.Errorf("node %d not present", i)
	}
	return (*s)[i], nil
}

func (s *nodeSlice) Append(value []byte) (uint64, error) {
	*s = append(*s, append([]byte(nil), value...))
	return uint64(len(*s)), nil
}

// TestCommittedTreeRebuildsFromItsLeaves: across in-memory rollovers, every
// stored node, including the interior nodes that bury an earlier massif's
// peaks, is the node a fresh MMR built from the same leaves has at that
// index. That holds only if each rolled-forward massif carried the right
// ancestor peak stack.
func TestCommittedTreeRebuildsFromItsLeaves(t *testing.T) {
	ctx := context.Background()
	client := merklelogtest.NewMemClient()
	c := newTestCommitter(t, client) // 4 leaves per massif
	logID := uuid.New()

	all := testEntries(21)
	for _, batch := range [][]ingress.Entry{all[:3], all[3:14], all[14:]} {
		_, err := c.CommitLogGroup(ctx, logID[:], batch)
		require.NoError(t, err)
	}

	store := openLogStore(t, client, logID, c.massifHeight)
	head, err := massifs.GetMassifHeadContext(ctx, store)
	require.NoError(t, err)
	require.Equal(t, uint32(5), head.Start.MassifIndex, "21 leaves in massifs of 4")

	stored := map[uint64][]byte{}
	var rebuilt nodeSlice
	for massifIndex := uint32(0); massifIndex <= head.Start.MassifIndex; massifIndex++ {
		mc, err := massifs.GetMassifContext(ctx, store, massifIndex)
		require.NoError(t, err)
		for i := mc.Start.FirstIndex; i < mc.RangeCount(); i++ {
			node, err := mc.Get(i)
			require.NoError(t, err)
			stored[i] = node
		}
		for ordinal := uint64(0); ordinal < mc.MassifLeafCount(); ordinal++ {
			leaf := stored[urkle.LeafOrdinalToMMRIndex(mc.Start.FirstIndex, ordinal)]
			_, err := mmr.AddHashedLeaf(&rebuilt, sha256.New(), leaf)
			require.NoError(t, err)
		}
	}

	require.Equal(t, len(rebuilt), len(stored), "node count")
	for i := range rebuilt {
		require.Equal(t, rebuilt[i], stored[uint64(i)], "node %d", i)
	}
}
