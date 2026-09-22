package publishproof

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/go-merklelog/massifs"
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

// encodeStoredGrantFromEmbedded wraps a pre-built grant v0 CBOR body
// (embedded) in a COSE Sign1 transparent statement, the way encodeStoredGrant
// does from individual fields. Used to feed the forestrie/protocol grant
// vectors (testdata/grant_vectors*.json) through decodeStoredGrant directly.
func encodeStoredGrantFromEmbedded(t *testing.T, embedded, idts []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(embedded)
	unprotected := map[int64]any{tHeaderForestrieGrant: embedded}
	if idts != nil {
		unprotected[tHeaderIdtimestamp] = idts
	}
	sign1 := []any{[]byte{0xa1, 0x01, 0x26}, unprotected, digest[:], make([]byte, 64)}
	out, err := cbor.Marshal(sign1)
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

// indexedFixtureMassif builds a massif the way ranger's committer does: for
// each (idtimestamp, contentHash) entry the mmr leaf is
// sha256(idtsBE || contentHash), appended and indexed under the idtimestamp.
// Returns the context and the resulting mmr size.
func indexedFixtureMassif(t *testing.T, entries []fixtureEntry) (*massifs.MassifContext, uint64) {
	t.Helper()
	mc, err := massifs.CreateFirstMassifContext(t.Context(), 0, fixtureMassifHeight)
	require.NoError(t, err)
	var size uint64
	for _, e := range entries {
		var idtsBE [8]byte
		binary.BigEndian.PutUint64(idtsBE[:], e.idts)
		leaf := sha256.Sum256(append(idtsBE[:], e.contentHash[:]...))
		size, err = mc.AddIndexedEntry(leaf[:])
		require.NoError(t, err)
		require.NoError(t, mc.IndexLeaf(e.idts, e.contentHash[:]))
	}
	return &mc, size
}

type fixtureEntry struct {
	idts        uint64
	contentHash [32]byte
}

// The grant leaf position is computable: idtimestamps are committed in
// strictly increasing order (ranger NextIDTimestamp), so leaf order equals
// key order and the v2 index leaf table binary-searches by idtimestamp. The
// mmr leaf at the found ordinal must verify as the grant leaf commitment.
func TestGrantLeafMMRIndex(t *testing.T) {
	entries := []fixtureEntry{
		{idts: 0, contentHash: sha256.Sum256([]byte("root-grant"))}, // zero-key root self-grant
		{idts: 100, contentHash: sha256.Sum256([]byte("g1"))},
		{idts: 250, contentHash: sha256.Sum256([]byte("g2"))},
		{idts: 251, contentHash: sha256.Sum256([]byte("g3"))},
	}
	mc, size := indexedFixtureMassif(t, entries)

	leafFor := func(e fixtureEntry) [32]byte {
		var idtsBE [8]byte
		binary.BigEndian.PutUint64(idtsBE[:], e.idts)
		return sha256.Sum256(append(idtsBE[:], e.contentHash[:]...))
	}

	// Every entry is found at its ordinal's node index, including the
	// zero-idtimestamp root grant at leaf 0.
	for i, e := range entries {
		var idts [8]byte
		binary.BigEndian.PutUint64(idts[:], e.idts)
		node, err := GrantLeafMMRIndex(mc, size, idts, leafFor(e))
		require.NoError(t, err)
		require.Equal(t, mmr.MMRIndex(uint64(i)), node)
	}

	// An idtimestamp between committed keys is absent.
	var absent [8]byte
	binary.BigEndian.PutUint64(absent[:], 200)
	_, err := GrantLeafMMRIndex(mc, size, absent, leafFor(entries[1]))
	require.ErrorIs(t, err, ErrGrantLeafNotFound)

	// A present idtimestamp whose leaf does not verify is an integrity failure
	// (the stored grant does not match what was sequenced), distinct from the
	// not-anchored case.
	var idts100 [8]byte
	binary.BigEndian.PutUint64(idts100[:], 100)
	_, err = GrantLeafMMRIndex(mc, size, idts100, [32]byte{0xde, 0xad})
	require.ErrorIs(t, err, ErrGrantLeafMismatch)

	// The on-chain bound is respected: a leaf beyond the anchored size is
	// not found even though it exists in the massif.
	var idts251 [8]byte
	binary.BigEndian.PutUint64(idts251[:], 251)
	boundSize := mmr.MMRIndex(3) // complete size covering only leaves 0..2
	_, err = GrantLeafMMRIndex(mc, boundSize, idts251, leafFor(entries[3]))
	require.ErrorIs(t, err, ErrGrantLeafNotFound)
}

// --- protocol grant-vector conformance (FOR-580: retired keys 7/8) ---
//
// grant_vectors.json and grant_vectors_negative.json under testdata/ are
// forestrie/protocol's conformance vectors for the keys 0-6 grant wire
// format (see testdata/SOURCE.grant_vectors for provenance). Their
// expected_cbor_hex / cbor_hex is the go-univocity "response form" (key 0
// idtimestamp present); decodeStoredGrant decodes only the embedded grant
// body (keys 1-6) and ignores an unused key 0, so the same bytes exercise
// both arbor decoders.

type protocolGrantVector struct {
	Description     string `json:"description"`
	LogIDHex        string `json:"log_id_hex"`
	OwnerLogIDHex   string `json:"owner_log_id_hex"`
	GrantFlagsHex   string `json:"grant_flags_hex"`
	MaxHeight       uint64 `json:"max_height"`
	MinGrowth       uint64 `json:"min_growth"`
	GrantDataHex    string `json:"grant_data_hex"`
	ExpectedCBORHex string `json:"expected_cbor_hex"`
}

type protocolGrantNegativeVector struct {
	Description  string `json:"description"`
	CBORHex      string `json:"cbor_hex"`
	MustReject   bool   `json:"must_reject"`
	Reason       string `json:"reason"`
	ObsoleteKeys []int  `json:"obsolete_keys"`
}

func loadProtocolGrantFixture(t *testing.T, name string, v interface{}) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, v))
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestDecodeStoredGrant_ProtocolVectors decodes the protocol positive
// vectors (keys 0-6) and checks every field.
func TestDecodeStoredGrant_ProtocolVectors(t *testing.T) {
	var vectors []protocolGrantVector
	loadProtocolGrantFixture(t, "grant_vectors.json", &vectors)
	require.NotEmpty(t, vectors, "fixture has no vectors")

	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			stmt := encodeStoredGrantFromEmbedded(t, mustHexBytes(t, v.ExpectedCBORHex), nil)
			got, err := decodeStoredGrant(stmt, requestAuthLog)
			require.NoError(t, err)

			wantLogID := logid.FromPaddedWire32(mustHexBytes(t, v.LogIDHex))
			require.Equal(t, wantLogID, got.LogID)
			wantOwnerLogID := logid.FromPaddedWire32(mustHexBytes(t, v.OwnerLogIDHex))
			require.Equal(t, wantOwnerLogID, got.OwnerLogID)

			wantFlags := new(big.Int).SetBytes(mustHexBytes(t, v.GrantFlagsHex))
			require.Equal(t, wantFlags, got.Grant.Grant)
			require.Equal(t, v.MaxHeight, got.Grant.MaxHeight)
			require.Equal(t, v.MinGrowth, got.Grant.MinGrowth)
			require.Equal(t, mustHexBytes(t, v.GrantDataHex), got.Grant.GrantData)
		})
	}
}

// TestDecodeStoredGrant_RejectsObsoleteKeys decodes the protocol negative
// vectors and checks every one is rejected; entries whose reason is
// obsolete_key must fail with ErrGrantObsoleteKey.
func TestDecodeStoredGrant_RejectsObsoleteKeys(t *testing.T) {
	var vectors []protocolGrantNegativeVector
	loadProtocolGrantFixture(t, "grant_vectors_negative.json", &vectors)
	require.NotEmpty(t, vectors, "fixture has no vectors")

	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			require.True(t, v.MustReject, "vector must_reject flag")
			stmt := encodeStoredGrantFromEmbedded(t, mustHexBytes(t, v.CBORHex), nil)
			_, err := decodeStoredGrant(stmt, requestAuthLog)
			require.Error(t, err)
			if v.Reason == "obsolete_key" {
				require.ErrorIs(t, err, ErrGrantObsoleteKey)
			}
		})
	}
}
