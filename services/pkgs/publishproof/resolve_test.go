package publishproof

import (
	"context"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// Genesis CBOR map labels (canopy forest-genesis-labels.ts; mirrored by the
// univocity service genesis_labels.go). Redeclared here so the tests pin the
// wire contract independently of the implementation.
const (
	tLabelGenesisVersion    = -68009
	tLabelBootstrapLogID    = -68010
	tLabelUnivocityAddr     = -68011
	tLabelUnivocityChainIDs = -68012 // legacy; must be rejected
	tLabelChainID           = -68013
)

// mapGetter is an in-memory ObjectGetter over the public grant-store layout.
type mapGetter map[string][]byte

func (m mapGetter) Get(_ context.Context, key string) ([]byte, error) {
	b, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%s: %w", key, massifstorage.ErrDoesNotExist)
	}
	return b, nil
}

type genesisOpts struct {
	version   any
	r         logid.UUID
	contract  common.Address
	chainID   any
	legacy    bool // include the rejected -68012 label
	tagged    bool // wrap the map and byte strings in CBOR tags (cbor-x interop)
	omitAddr  bool
	shortBoot bool // bootstrap-logid not 32 bytes
}

func encodeGenesis(t *testing.T, o genesisOpts) []byte {
	t.Helper()
	boot := o.r.ToPaddedWire32()
	m := map[int64]any{}
	if o.version != nil {
		m[tLabelGenesisVersion] = o.version
	}
	if o.shortBoot {
		m[tLabelBootstrapLogID] = boot[16:]
	} else if o.tagged {
		// cbor-x encodes Uint8Array fields as tagged byte strings (tag 64).
		m[tLabelBootstrapLogID] = cbor.Tag{Number: 64, Content: boot[:]}
	} else {
		m[tLabelBootstrapLogID] = boot[:]
	}
	if !o.omitAddr {
		if o.tagged {
			m[tLabelUnivocityAddr] = cbor.Tag{Number: 64, Content: o.contract.Bytes()}
		} else {
			m[tLabelUnivocityAddr] = o.contract.Bytes()
		}
	}
	if o.chainID != nil {
		m[tLabelChainID] = o.chainID
	}
	if o.legacy {
		m[tLabelUnivocityChainIDs] = []any{uint64(1)}
	}
	var doc any = m
	if o.tagged {
		// cbor-x wraps maps in a tag; the parser must unwrap any tag chain.
		doc = cbor.Tag{Number: 259, Content: m}
	}
	out, err := cbor.Marshal(doc)
	require.NoError(t, err)
	return out
}

func testLogID(t *testing.T, s string) logid.UUID {
	t.Helper()
	id, err := logid.ParseUUIDString(s)
	require.NoError(t, err)
	return id
}

func indexKeyFor(id logid.UUID) string   { return "forests/index/forest/" + id.String() }
func genesisKeyFor(id logid.UUID) string { return "forests/forest/" + id.String() + "/genesis.cbor" }

// A granted (indexed) log resolves through the global logId->R index to its
// forest genesis chain binding (ADR-0036, ADR-0034, ADR-0047).
func TestResolveForestContractIndexedLog(t *testing.T) {
	r := testLogID(t, "10000000-0000-4000-8000-000000000001")
	dataLog := testLogID(t, "20000000-0000-4000-8000-000000000002")
	contract := common.HexToAddress("0x00000000000000000000000000000000000C0DE0")

	store := mapGetter{
		indexKeyFor(dataLog): []byte(r.String() + "\n"),
		genesisKeyFor(r): encodeGenesis(t, genesisOpts{
			version: uint64(1), r: r, contract: contract, chainID: "84532",
		}),
	}

	got, err := ResolveForestContract(t.Context(), store, dataLog)
	require.NoError(t, err)
	require.Equal(t, r, got.R)
	require.Equal(t, uint64(84532), got.ChainID)
	require.Equal(t, contract, got.Contract)
}

// The forest root R resolves even when its self-index entry is absent: the
// resolver falls back to probing the genesis object keyed by the logId itself
// (genesis self-indexing is best effort on POST).
func TestResolveForestContractSelfRootWithoutIndex(t *testing.T) {
	r := testLogID(t, "10000000-0000-4000-8000-000000000001")
	contract := common.HexToAddress("0x00000000000000000000000000000000000C0DE0")

	store := mapGetter{
		genesisKeyFor(r): encodeGenesis(t, genesisOpts{
			version: uint64(2), r: r, contract: contract, chainID: "1",
		}),
	}

	got, err := ResolveForestContract(t.Context(), store, r)
	require.NoError(t, err)
	require.Equal(t, r, got.R)
	require.Equal(t, uint64(1), got.ChainID)
	require.Equal(t, contract, got.Contract)
}

// cbor-x (canopy) wraps maps and Uint8Array values in CBOR tags; the resolver
// must unwrap them (interop parity with the univocity service parser).
func TestResolveForestContractTaggedGenesis(t *testing.T) {
	r := testLogID(t, "10000000-0000-4000-8000-000000000001")
	contract := common.HexToAddress("0x00000000000000000000000000000000000C0DE0")

	store := mapGetter{
		genesisKeyFor(r): encodeGenesis(t, genesisOpts{
			version: uint64(1), r: r, contract: contract, chainID: "84532", tagged: true,
		}),
	}

	got, err := ResolveForestContract(t.Context(), store, r)
	require.NoError(t, err)
	require.Equal(t, contract, got.Contract)
	require.Equal(t, uint64(84532), got.ChainID)
}

func TestResolveForestContractNotResolved(t *testing.T) {
	r := testLogID(t, "10000000-0000-4000-8000-000000000001")
	dataLog := testLogID(t, "20000000-0000-4000-8000-000000000002")
	contract := common.HexToAddress("0x00000000000000000000000000000000000C0DE0")
	valid := func() []byte {
		return encodeGenesis(t, genesisOpts{
			version: uint64(1), r: r, contract: contract, chainID: "84532",
		})
	}

	cases := []struct {
		name    string
		store   mapGetter
		logID   logid.UUID
		errIs   error
		errText string
	}{
		{
			name:  "unknown log: no index, no self genesis",
			store: mapGetter{},
			logID: dataLog,
			errIs: ErrForestNotResolved,
		},
		{
			name: "dangling index: genesis missing for R",
			store: mapGetter{
				indexKeyFor(dataLog): []byte(r.String()),
			},
			logID: dataLog,
			errIs: ErrForestNotResolved,
		},
		{
			name: "corrupt index body",
			store: mapGetter{
				indexKeyFor(dataLog): []byte("not-a-uuid"),
				genesisKeyFor(r):     valid(),
			},
			logID:   dataLog,
			errText: "index",
		},
		{
			name: "genesis R mismatch with object key",
			store: mapGetter{
				indexKeyFor(dataLog): []byte(r.String()),
				genesisKeyFor(r): encodeGenesis(t, genesisOpts{
					version:  uint64(1),
					r:        testLogID(t, "30000000-0000-4000-8000-000000000003"),
					contract: contract, chainID: "84532",
				}),
			},
			logID:   dataLog,
			errText: "bootstrap-logid",
		},
		{
			name: "legacy univocity-chainids rejected",
			store: mapGetter{
				genesisKeyFor(r): encodeGenesis(t, genesisOpts{
					version: uint64(1), r: r, contract: contract, chainID: "84532", legacy: true,
				}),
			},
			logID:   r,
			errText: "legacy",
		},
		{
			name: "unsupported genesis version",
			store: mapGetter{
				genesisKeyFor(r): encodeGenesis(t, genesisOpts{
					version: uint64(3), r: r, contract: contract, chainID: "84532",
				}),
			},
			logID:   r,
			errText: "genesis-version",
		},
		{
			name: "chain-id must be a decimal string",
			store: mapGetter{
				genesisKeyFor(r): encodeGenesis(t, genesisOpts{
					version: uint64(1), r: r, contract: contract, chainID: uint64(84532),
				}),
			},
			logID:   r,
			errText: "chain-id",
		},
		{
			name: "chain-id over 10 digits rejected",
			store: mapGetter{
				genesisKeyFor(r): encodeGenesis(t, genesisOpts{
					version: uint64(1), r: r, contract: contract, chainID: "18446744073709551616",
				}),
			},
			logID:   r,
			errText: "chain-id",
		},
		{
			name: "univocity-addr must be 20 bytes",
			store: mapGetter{
				genesisKeyFor(r): encodeGenesis(t, genesisOpts{
					version: uint64(1), r: r, contract: contract, chainID: "84532", omitAddr: true,
				}),
			},
			logID:   r,
			errText: "univocity-addr",
		},
		{
			name: "bootstrap-logid must be 32 bytes",
			store: mapGetter{
				genesisKeyFor(r): encodeGenesis(t, genesisOpts{
					version: uint64(1), r: r, contract: contract, chainID: "84532", shortBoot: true,
				}),
			},
			logID:   r,
			errText: "bootstrap-logid",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveForestContract(t.Context(), tc.store, tc.logID)
			require.Error(t, err)
			if tc.errIs != nil {
				require.ErrorIs(t, err, tc.errIs)
			}
			if tc.errText != "" {
				require.Contains(t, err.Error(), tc.errText)
			}
		})
	}
}
