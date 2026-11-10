package publishproof

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/forestrie/go-merklelog/urkle"
)

// GrantLeaf is a create grant's leaf found in its owner log.
type GrantLeaf struct {
	// MMRIndex is the global mmr node index of the leaf.
	MMRIndex uint64
	// LeafIndex is the global leaf ordinal.
	LeafIndex uint64
	// IDTimestampBe is the idtimestamp the leaf was sequenced under, read from
	// the owner massif's leaf table.
	IDTimestampBe [8]byte
	// Leaf is sha256(IDTimestampBe || contentHash).
	Leaf [32]byte
}

// StoredGrantContentHash decodes a stored grant transparent statement (the raw
// COSE bytes the public grant store holds) and returns the grant's content
// hash, the value ranger commits under the grant's idtimestamp. It does not
// need the idtimestamp header, which may be absent or still zero.
func StoredGrantContentHash(raw []byte) ([32]byte, error) {
	sg, err := decodeStoredGrant(clampObject(raw), requestAuthLog)
	if err != nil {
		return [32]byte{}, err
	}
	return sg.ContentHash()
}

// ScanGrantLeaf finds a create grant's leaf in its owner log when the grant's
// idtimestamp is not known. It examines owner leaves with global leaf index in
// [fromLeaf, leaves present now) and returns the first whose node equals
// sha256(idtimestamp || contentHash), reading each idtimestamp from the
// massif's leaf table.
//
// On a match it returns (leaf, true, next, nil) where next is the leaf index
// after the match. When nothing matches it returns (zero, false, next, nil)
// where next is the number of leaves examined up to, so a later call with
// fromLeaf = next scans only leaves appended since. Massifs wholly before
// fromLeaf are not read. An owner log with no massifs yet is
// (zero, false, fromLeaf, nil).
//
// The reader must reflect the owner log's current state; a reader that caches
// the head massif will not show later appends.
func ScanGrantLeaf(
	ctx context.Context, owner massifs.ObjectReader, contentHash [32]byte, fromLeaf uint64,
) (GrantLeaf, bool, uint64, error) {
	head, err := owner.HeadIndex(ctx, massifstorage.ObjectMassifData)
	if errors.Is(err, massifstorage.ErrLogEmpty) {
		return GrantLeaf{}, false, fromLeaf, nil
	}
	if err != nil {
		return GrantLeaf{}, false, fromLeaf, fmt.Errorf("owner log head massif: %w", err)
	}

	// Every massif holds the same number of leaves, so the first massif that can
	// contain fromLeaf is known from the head massif's height without reading
	// the earlier ones.
	headMC, err := massifs.GetMassifContext(ctx, owner, head)
	if err != nil {
		return GrantLeaf{}, false, fromLeaf, fmt.Errorf("read owner massif %d: %w", head, err)
	}
	perMassif := uint64(1) << (headMC.Start.MassifHeight - 1)
	first := fromLeaf / perMassif
	if first > uint64(head) {
		return GrantLeaf{}, false, fromLeaf, nil
	}

	next := fromLeaf
	for mi := uint32(first); mi <= head; mi++ {
		mc := headMC
		if mi != head {
			if mc, err = massifs.GetMassifContext(ctx, owner, mi); err != nil {
				return GrantLeaf{}, false, next, fmt.Errorf("read owner massif %d: %w", mi, err)
			}
		}
		gl, found, end, err := scanMassif(&mc, contentHash, fromLeaf)
		if err != nil {
			return GrantLeaf{}, false, next, err
		}
		if found {
			return gl, true, gl.LeafIndex + 1, nil
		}
		next = max(next, end)
	}
	return GrantLeaf{}, false, next, nil
}

// scanMassif looks for the grant leaf among the massif's leaves at or after
// global leaf fromLeaf. It returns the global leaf index one past the massif's
// last leaf.
func scanMassif(
	mc *massifs.MassifContext, contentHash [32]byte, fromLeaf uint64,
) (GrantLeaf, bool, uint64, error) {
	leafTable, err := mc.UrkleLeafTableRegion()
	if err != nil {
		return GrantLeaf{}, false, 0, fmt.Errorf("owner massif %d index leaf table: %w", mc.Start.MassifIndex, err)
	}
	massifFirstLeaf := mmr.LeafCount(mc.Start.FirstIndex)
	count := mc.MassifLeafCount()

	var ordinal uint64
	if fromLeaf > massifFirstLeaf {
		ordinal = fromLeaf - massifFirstLeaf
	}
	for ; ordinal < count; ordinal++ {
		var idts [8]byte
		binary.BigEndian.PutUint64(idts[:], urkle.LeafKey(leafTable, uint32(ordinal)))
		leaf := sha256.Sum256(append(idts[:], contentHash[:]...))

		nodeIndex := urkle.LeafOrdinalToMMRIndex(mc.Start.FirstIndex, ordinal)
		node, err := mc.Get(nodeIndex)
		if err != nil {
			return GrantLeaf{}, false, 0, fmt.Errorf("read owner log leaf %d (node %d): %w", massifFirstLeaf+ordinal, nodeIndex, err)
		}
		if string(node) == string(leaf[:]) {
			return GrantLeaf{
				MMRIndex:      nodeIndex,
				LeafIndex:     massifFirstLeaf + ordinal,
				IDTimestampBe: idts,
				Leaf:          leaf,
			}, true, massifFirstLeaf + count, nil
		}
	}
	return GrantLeaf{}, false, massifFirstLeaf + count, nil
}

// GrantLeafIndex caches leaf-scan progress per (owner log id, content hash). It
// is safe for concurrent use. A found position is cached for good, since leaf
// positions never change; a miss resumes from where the previous scan stopped.
type GrantLeafIndex struct {
	mu      sync.Mutex
	entries map[grantLeafKey]*grantLeafEntry
}

type grantLeafKey struct {
	owner       logid.UUID
	contentHash [32]byte
}

type grantLeafEntry struct {
	mu     sync.Mutex // serialises scans of one key
	found  bool
	leaf   GrantLeaf
	cursor uint64
}

// NewGrantLeafIndex returns an empty GrantLeafIndex.
func NewGrantLeafIndex() *GrantLeafIndex {
	return &GrantLeafIndex{entries: map[grantLeafKey]*grantLeafEntry{}}
}

// Find returns the grant leaf for contentHash in the owner log, scanning only
// leaves not yet examined for this key. found is false while the leaf has not
// been sequenced into the owner log. The reader must reflect the owner log's
// current state (see ScanGrantLeaf).
func (x *GrantLeafIndex) Find(
	ctx context.Context, ownerLogID logid.UUID, owner massifs.ObjectReader, contentHash [32]byte,
) (GrantLeaf, bool, error) {
	key := grantLeafKey{owner: ownerLogID, contentHash: contentHash}
	x.mu.Lock()
	e, ok := x.entries[key]
	if !ok {
		e = &grantLeafEntry{}
		x.entries[key] = e
	}
	x.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.found {
		return e.leaf, true, nil
	}
	gl, found, next, err := ScanGrantLeaf(ctx, owner, contentHash, e.cursor)
	if err != nil {
		return GrantLeaf{}, false, err
	}
	e.cursor = next
	if found {
		e.found, e.leaf = true, gl
	}
	return gl, found, nil
}

// VerifyGrantLeafAnchored reports whether gl is covered by the owner's
// published on-chain state. A leaf at or beyond state.Size is not covered yet
// and yields (false, nil). A covered leaf must have an inclusion proof, built
// from the owner's massifs at state.Size, that reproduces a peak of
// state.Accumulator; failure to build or match is an error, since a covered
// leaf that does not verify means the owner log and the on-chain state
// disagree.
func VerifyGrantLeafAnchored(
	ctx context.Context, owner massifs.ObjectReader, massifHeight uint8, state LogState, gl GrantLeaf,
) (bool, error) {
	if gl.MMRIndex >= state.Size {
		return false, nil
	}
	nodes := newOwnerNodeGetter(ctx, owner, massifHeight)
	proof, err := BuildInclusionProof(nodes, state.Size, gl.MMRIndex)
	if err != nil {
		return false, err
	}
	if err := verifyGrantInclusion(gl.Leaf, proof, state.Accumulator); err != nil {
		return false, err
	}
	return true, nil
}
