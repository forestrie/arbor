package committer

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/urkle"
	"github.com/stretchr/testify/require"
)

func TestAppendThenIndexFlow_UsingAddIndexedEntry(t *testing.T) {
	mc, err := massifs.CreateFirstMassifContext(context.Background(), 1, 3)
	require.NoError(t, err)

	idTimestamp := uint64(0x0102030405060708)
	contentHash := sha256.Sum256([]byte("content-1"))

	// leafHash = H(idTimestampBytes || contentHash)
	var idTimestampBytes [8]byte
	binary.BigEndian.PutUint64(idTimestampBytes[:], idTimestamp)
	h := sha256.New()
	h.Write(idTimestampBytes[:])
	h.Write(contentHash[:])
	leafHash := h.Sum(nil)
	require.Len(t, leafHash, massifs.ValueBytes)

	_, err = mc.AddIndexedEntry(leafHash)
	require.NoError(t, err)

	// Update v2 index structures (Urkle + Bloom).
	// IndexLeaf stores contentHash (content-hash) directly in the trie valueBytes,
	// not the MMR leaf hash. This enables direct verification of (idtimestamp, content)
	// pair exclusion.
	err = mc.IndexLeaf(idTimestamp, contentHash[:])
	require.NoError(t, err)

	mc.SetLastIDTimestamp(idTimestamp)
	require.Equal(t, idTimestamp, mc.Start.LastID)
	require.Equal(t, idTimestamp, mc.GetLastIDTimestamp())

	leafTable, err := mc.UrkleLeafTableRegion()
	require.NoError(t, err)
	require.Equal(t, idTimestamp, urkle.LeafKey(leafTable, 0))
	// Verify that the trie stores the content-hash directly, not the MMR leaf hash.
	require.Equal(t, contentHash, urkle.LeafValue(leafTable, 0))
}
