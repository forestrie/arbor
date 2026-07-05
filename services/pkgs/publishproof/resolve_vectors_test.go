package publishproof

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// resolveVectors is the shared conformance fixture set for forest contract
// resolution (ADR-0047 mitigation: the univocity service resolution and
// publishproof.ResolveForestContract must both pass these; divergence fails a
// test, not production). Regenerate with:
//
//	UPDATE_RESOLVE_VECTORS=1 go test -run TestResolveVectors ./...
type resolveVectors struct {
	Description string          `json:"description"`
	Vectors     []resolveVector `json:"vectors"`
}

type resolveVector struct {
	Name string `json:"name"`
	// LogID is the canonical UUID being resolved.
	LogID string `json:"logId"`
	// Objects is the public grant-store content: object key -> base64 body.
	Objects map[string]string `json:"objects"`
	// Want is the expected binding; empty when WantError is set.
	Want *resolveWant `json:"want,omitempty"`
	// WantError is a required substring of the error; "not-resolved" vectors
	// additionally must match ErrForestNotResolved.
	WantError   string `json:"wantError,omitempty"`
	NotResolved bool   `json:"notResolved,omitempty"`
}

type resolveWant struct {
	R        string `json:"r"`
	ChainID  uint64 `json:"chainId"`
	Contract string `json:"contract"`
}

const resolveVectorsPath = "testdata/resolve-vectors.json"

func buildResolveVectors(t *testing.T) resolveVectors {
	t.Helper()
	r := testLogID(t, "10000000-0000-4000-8000-000000000001")
	dataLog := testLogID(t, "20000000-0000-4000-8000-000000000002")
	otherR := testLogID(t, "30000000-0000-4000-8000-000000000003")
	contract := common.HexToAddress("0x00000000000000000000000000000000000C0DE0")

	genesisV1 := encodeGenesis(t, genesisOpts{
		version: uint64(1), r: r, contract: contract, chainID: "84532",
	})
	b64 := base64.StdEncoding.EncodeToString

	return resolveVectors{
		Description: "Forest contract resolution conformance vectors (ADR-0047). " +
			"Object keys are the public grant-store layout; bodies are base64. " +
			"Both the univocity service resolution and publishproof must agree.",
		Vectors: []resolveVector{
			{
				Name:  "indexed data log resolves via index to genesis binding",
				LogID: dataLog.String(),
				Objects: map[string]string{
					indexKeyFor(dataLog): b64([]byte(r.String())),
					genesisKeyFor(r):     b64(genesisV1),
				},
				Want: &resolveWant{R: r.String(), ChainID: 84532, Contract: contract.Hex()},
			},
			{
				Name:  "forest root resolves without an index entry (self genesis)",
				LogID: r.String(),
				Objects: map[string]string{
					genesisKeyFor(r): b64(genesisV1),
				},
				Want: &resolveWant{R: r.String(), ChainID: 84532, Contract: contract.Hex()},
			},
			{
				Name:  "genesis v2 accepted",
				LogID: r.String(),
				Objects: map[string]string{
					genesisKeyFor(r): b64(encodeGenesis(t, genesisOpts{
						version: uint64(2), r: r, contract: contract, chainID: "1",
					})),
				},
				Want: &resolveWant{R: r.String(), ChainID: 1, Contract: contract.Hex()},
			},
			{
				Name:  "cbor-x tagged map and byte strings accepted",
				LogID: r.String(),
				Objects: map[string]string{
					genesisKeyFor(r): b64(encodeGenesis(t, genesisOpts{
						version: uint64(1), r: r, contract: contract, chainID: "84532", tagged: true,
					})),
				},
				Want: &resolveWant{R: r.String(), ChainID: 84532, Contract: contract.Hex()},
			},
			{
				Name:        "unknown log is not resolved",
				LogID:       dataLog.String(),
				Objects:     map[string]string{},
				NotResolved: true,
			},
			{
				Name:  "dangling index (missing genesis) is not resolved",
				LogID: dataLog.String(),
				Objects: map[string]string{
					indexKeyFor(dataLog): b64([]byte(r.String())),
				},
				NotResolved: true,
			},
			{
				Name:  "genesis bootstrap-logid must match its object key",
				LogID: r.String(),
				Objects: map[string]string{
					genesisKeyFor(r): b64(encodeGenesis(t, genesisOpts{
						version: uint64(1), r: otherR, contract: contract, chainID: "84532",
					})),
				},
				WantError: "bootstrap-logid",
			},
			{
				Name:  "legacy univocity-chainids rejected",
				LogID: r.String(),
				Objects: map[string]string{
					genesisKeyFor(r): b64(encodeGenesis(t, genesisOpts{
						version: uint64(1), r: r, contract: contract, chainID: "84532", legacy: true,
					})),
				},
				WantError: "legacy",
			},
			{
				Name:  "non-string chain-id rejected",
				LogID: r.String(),
				Objects: map[string]string{
					genesisKeyFor(r): b64(encodeGenesis(t, genesisOpts{
						version: uint64(1), r: r, contract: contract, chainID: uint64(84532),
					})),
				},
				WantError: "chain-id",
			},
		},
	}
}

// TestResolveVectors regenerates (with UPDATE_RESOLVE_VECTORS=1) and then
// runs the committed conformance vectors through ResolveForestContract.
func TestResolveVectors(t *testing.T) {
	if os.Getenv("UPDATE_RESOLVE_VECTORS") == "1" {
		vs := buildResolveVectors(t)
		out, err := json.MarshalIndent(vs, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Dir(resolveVectorsPath), 0o755))
		require.NoError(t, os.WriteFile(resolveVectorsPath, append(out, '\n'), 0o644))
	}

	raw, err := os.ReadFile(resolveVectorsPath)
	require.NoError(t, err, "run once with UPDATE_RESOLVE_VECTORS=1 to generate")
	var vs resolveVectors
	require.NoError(t, json.Unmarshal(raw, &vs))
	require.NotEmpty(t, vs.Vectors)

	for _, v := range vs.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			store := mapGetter{}
			for key, b64body := range v.Objects {
				body, err := base64.StdEncoding.DecodeString(b64body)
				require.NoError(t, err)
				store[key] = body
			}
			got, err := ResolveForestContract(context.Background(), store, testLogID(t, v.LogID))
			if v.Want != nil {
				require.NoError(t, err)
				require.Equal(t, v.Want.R, got.R.String())
				require.Equal(t, v.Want.ChainID, got.ChainID)
				require.Equal(t, common.HexToAddress(v.Want.Contract), got.Contract)
				return
			}
			require.Error(t, err)
			if v.NotResolved {
				require.ErrorIs(t, err, ErrForestNotResolved)
			}
			if v.WantError != "" {
				require.Contains(t, err.Error(), v.WantError)
			}
		})
	}
}
