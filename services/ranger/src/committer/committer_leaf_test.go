package committer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog/merklelogtest"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/urkle"
	"github.com/google/uuid"
)

// wantLeaf spells out the MMR profile "option D" leaf (FOR-726)
// independently of the committer:
//
//	H(0x00 || pos || H(0x01 || idtimestamp) || contentHash), pos = mmrIndex+1
//
// with pos and the idtimestamp as 8 bytes big-endian. 0x01 || idtimestamp is
// Forestrie's ts-leaf-data.
func wantLeaf(mmrIndex, idTimestamp uint64, contentHash [32]byte) []byte {
	var tsLeafData [9]byte
	tsLeafData[0] = 0x01
	binary.BigEndian.PutUint64(tsLeafData[1:], idTimestamp)
	tsLeafDataHash := sha256.Sum256(tsLeafData[:])

	x := []byte{0x00}
	x = binary.BigEndian.AppendUint64(x, mmrIndex+1)
	x = append(x, tsLeafDataHash[:]...)
	x = append(x, contentHash[:]...)
	leaf := sha256.Sum256(x)
	return leaf[:]
}

// TestCommittedLeavesBindTheirPosition: every leaf in the log commits the
// position it is stored at, so an inclusion proof with an empty path still
// binds the index. Rollovers and failed batches are where a position fixed
// too early would go stale: a failed batch leaves the massif it filled
// behind, and the redelivery appends at new positions.
func TestCommittedLeavesBindTheirPosition(t *testing.T) {
	tests := []struct {
		name string
		// batches are committed in order; a batch with bad >= 0 carries a
		// 31-byte content hash at that entry and must fail.
		batches []struct{ n, bad int }
		// leaves in the log afterwards, unreferenced duplicates included.
		wantLeaves uint64
	}{
		{
			name:       "batch across two rollovers",
			batches:    []struct{ n, bad int }{{n: 10, bad: -1}},
			wantLeaves: 10,
		},
		{
			name:       "failed batch after a rollover, then redelivered",
			batches:    []struct{ n, bad int }{{n: 10, bad: 7}, {n: 10, bad: -1}},
			wantLeaves: 4 + 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			client := merklelogtest.NewMemClient()
			c := newTestCommitter(t, client) // 4 leaves per massif
			logID := uuid.New()

			for _, b := range tt.batches {
				entries := testEntries(b.n)
				if b.bad >= 0 {
					entries[b.bad].ContentHash = entries[b.bad].ContentHash[:31]
				}
				_, err := c.CommitLogGroup(ctx, logID[:], entries)
				if (err != nil) != (b.bad >= 0) {
					t.Fatalf("CommitLogGroup(n=%d, bad=%d) err = %v", b.n, b.bad, err)
				}
			}

			store := openLogStore(t, client, logID, c.massifHeight)
			head, err := massifs.GetMassifHeadContext(ctx, store)
			if err != nil {
				t.Fatalf("GetMassifHeadContext: %v", err)
			}
			var leaves uint64
			for massifIndex := uint32(0); massifIndex <= head.Start.MassifIndex; massifIndex++ {
				mc, err := massifs.GetMassifContext(ctx, store, massifIndex)
				if err != nil {
					t.Fatalf("GetMassifContext(%d): %v", massifIndex, err)
				}
				leafTable, err := mc.UrkleLeafTableRegion()
				if err != nil {
					t.Fatalf("massif %d leaf table: %v", massifIndex, err)
				}
				for ordinal := uint64(0); ordinal < mc.MassifLeafCount(); ordinal++ {
					mmrIndex := urkle.LeafOrdinalToMMRIndex(mc.Start.FirstIndex, ordinal)
					got, err := mc.Get(mmrIndex)
					if err != nil {
						t.Fatalf("read leaf at %d: %v", mmrIndex, err)
					}
					want := wantLeaf(mmrIndex,
						urkle.LeafKey(leafTable, uint32(ordinal)),
						urkle.LeafValue(leafTable, uint32(ordinal)))
					if !bytes.Equal(got, want) {
						t.Errorf("leaf at mmrIndex %d = %x, want %x (bound to pos %d)",
							mmrIndex, got, want, mmrIndex+1)
					}
					leaves++
				}
			}
			if leaves != tt.wantLeaves {
				t.Errorf("checked %d leaves, want %d", leaves, tt.wantLeaves)
			}
		})
	}
}
