package publishproof

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/logid"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// Grant transparent-statement wire labels (canopy grant/transparent-statement.ts,
// mirrored by the univocity service grant.go). Redeclared so the tests pin the
// wire contract independently of the implementation.
const (
	tHeaderIdtimestamp    = -65537
	tHeaderForestrieGrant = -65538
	tGrantKeyLogID        = 1
	tGrantKeyOwnerLogID   = 2
	tGrantKeyFlags        = 3
	tGrantKeyMaxHeight    = 4
	tGrantKeyMinGrowth    = 5
	tGrantKeyGrantData    = 6
)

type storedGrantOpts struct {
	logID       logid.UUID
	ownerLogID  logid.UUID
	flags       []byte
	maxHeight   uint64
	minGrowth   uint64
	grantData   []byte
	idts        []byte
	breakDigest bool
	tag18       bool
}

// encodeStoredGrant builds a stored grant transparent statement: a COSE Sign1
// whose payload is sha256 of the embedded grant v0 CBOR (unprotected -65538),
// with the sequenced idtimestamp in unprotected -65537.
func encodeStoredGrant(t *testing.T, o storedGrantOpts) []byte {
	t.Helper()
	logWire := o.logID.ToPaddedWire32()
	ownerWire := o.ownerLogID.ToPaddedWire32()
	grantV0, err := cbor.Marshal(map[int64]any{
		tGrantKeyLogID:      logWire[:],
		tGrantKeyOwnerLogID: ownerWire[:],
		tGrantKeyFlags:      o.flags,
		tGrantKeyMaxHeight:  o.maxHeight,
		tGrantKeyMinGrowth:  o.minGrowth,
		tGrantKeyGrantData:  o.grantData,
	})
	require.NoError(t, err)

	digest := sha256.Sum256(grantV0)
	if o.breakDigest {
		digest[0] ^= 0xff
	}
	unprotected := map[int64]any{tHeaderForestrieGrant: grantV0}
	if o.idts != nil {
		unprotected[tHeaderIdtimestamp] = o.idts
	}
	sign1 := []any{[]byte{0xa1, 0x01, 0x26}, unprotected, digest[:], make([]byte, 64)}
	var doc any = sign1
	if o.tag18 {
		doc = cbor.Tag{Number: 18, Content: sign1}
	}
	out, err := cbor.Marshal(doc)
	require.NoError(t, err)
	return out
}

func grantKeyForTest(r, subject logid.UUID, class string) string {
	return "forests/forest/" + r.String() + "/grants/" + class + "/" + subject.String() + ".cbor"
}

var (
	testFlagsExtendData = []byte{0, 0, 0, 0, 0, 0, 0, 2} // GF_DATA_LOG (low bit 1)
	testIdts            = []byte{0, 0, 0, 0, 0, 0, 0, 7}
)

// A stored data-log grant yields the calldata PublishGrant (flags in the low
// bytes of the uint256 grant, request from the grant class) and the sequenced
// idtimestamp.
func TestReadStoredGrantDataLog(t *testing.T) {
	r := testLogID(t, "10000000-0000-4000-8000-000000000001")
	dataLog := testLogID(t, "20000000-0000-4000-8000-000000000002")
	grantData := make([]byte, 64)
	grantData[0] = 0xab

	store := mapGetter{
		grantKeyForTest(r, dataLog, "data-log"): encodeStoredGrant(t, storedGrantOpts{
			logID: dataLog, ownerLogID: r, flags: testFlagsExtendData,
			maxHeight: 1000, minGrowth: 2, grantData: grantData, idts: testIdts,
			tag18: true,
		}),
	}

	got, err := ReadStoredGrant(t.Context(), store, r, dataLog)
	require.NoError(t, err)

	require.Equal(t, dataLog, got.LogID)
	require.Equal(t, r, got.OwnerLogID)
	require.Equal(t, [8]byte(testIdts), got.IDTimestampBe)

	wantLog := dataLog.ToPaddedWire32()
	wantOwner := r.ToPaddedWire32()
	require.Equal(t, wantLog, got.Grant.LogId)
	require.Equal(t, wantOwner, got.Grant.OwnerLogId)
	require.Equal(t, big.NewInt(2), got.Grant.Grant)
	require.Equal(t, uint64(1000), got.Grant.MaxHeight)
	require.Equal(t, uint64(2), got.Grant.MinGrowth)
	require.Equal(t, grantData, got.Grant.GrantData)
	// data-log class -> GC_DATA_LOG request (2 << 224).
	require.Equal(t, new(big.Int).Lsh(big.NewInt(2), 224), got.Grant.Request)
}

// When no data-log grant exists the auth-log class is consulted, and the
// request becomes GC_AUTH_LOG. A missing idtimestamp header is the zero
// idtimestamp (the root self-grant convention).
func TestReadStoredGrantAuthLogFallback(t *testing.T) {
	r := testLogID(t, "10000000-0000-4000-8000-000000000001")

	store := mapGetter{
		grantKeyForTest(r, r, "auth-log"): encodeStoredGrant(t, storedGrantOpts{
			logID: r, ownerLogID: r, flags: []byte{0, 0, 0, 3, 0, 0, 0, 1},
			maxHeight: 0, minGrowth: 0, grantData: make([]byte, 20),
		}),
	}

	got, err := ReadStoredGrant(t.Context(), store, r, r)
	require.NoError(t, err)
	require.Equal(t, [8]byte{}, got.IDTimestampBe)
	require.Equal(t, new(big.Int).SetBytes([]byte{0, 0, 0, 3, 0, 0, 0, 1}), got.Grant.Grant)
	// auth-log class -> GC_AUTH_LOG request (1 << 224).
	require.Equal(t, new(big.Int).Lsh(big.NewInt(1), 224), got.Grant.Request)
}

func TestReadStoredGrantErrors(t *testing.T) {
	r := testLogID(t, "10000000-0000-4000-8000-000000000001")
	dataLog := testLogID(t, "20000000-0000-4000-8000-000000000002")

	t.Run("absent in both classes", func(t *testing.T) {
		_, err := ReadStoredGrant(t.Context(), mapGetter{}, r, dataLog)
		require.ErrorIs(t, err, massifstorage.ErrDoesNotExist)
	})

	t.Run("payload digest mismatch", func(t *testing.T) {
		store := mapGetter{
			grantKeyForTest(r, dataLog, "data-log"): encodeStoredGrant(t, storedGrantOpts{
				logID: dataLog, ownerLogID: r, flags: testFlagsExtendData,
				grantData: make([]byte, 64), idts: testIdts, breakDigest: true,
			}),
		}
		_, err := ReadStoredGrant(t.Context(), store, r, dataLog)
		require.ErrorContains(t, err, "digest")
	})

	t.Run("subject mismatch", func(t *testing.T) {
		other := testLogID(t, "30000000-0000-4000-8000-000000000003")
		store := mapGetter{
			grantKeyForTest(r, dataLog, "data-log"): encodeStoredGrant(t, storedGrantOpts{
				logID: other, ownerLogID: r, flags: testFlagsExtendData,
				grantData: make([]byte, 64), idts: testIdts,
			}),
		}
		_, err := ReadStoredGrant(t.Context(), store, r, dataLog)
		require.ErrorContains(t, err, "subject")
	})
}

// The grant leaf is located in the owner log by scanning leaf positions for
// the grant's leaf commitment — content-agnostic, so other leaf kinds in the
// authority log are skipped over.
func TestFindGrantLeafIndex(t *testing.T) {
	store, sizes := newFixtureMMR(t, 5)
	size := sizes[4]

	// The fixture leaves are sha256(i); pick leaf ordinal 3 as "the grant".
	wantNode := mmr.MMRIndex(3)
	leafValue, err := store.Get(wantNode)
	require.NoError(t, err)

	node, err := FindGrantLeafIndex(store, size, [32]byte(leafValue))
	require.NoError(t, err)
	require.Equal(t, wantNode, node)

	_, err = FindGrantLeafIndex(store, size, [32]byte{0xde, 0xad})
	require.ErrorIs(t, err, ErrGrantLeafNotFound)
}
