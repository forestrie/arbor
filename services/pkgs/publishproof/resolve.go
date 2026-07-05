package publishproof

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/fxamacker/cbor/v2"
)

// Multi-forest contract resolution from public R2 (ADR-0047, plan-2607-02 D1).
//
// One deployment hosts many forests, each rooted on its own univocity
// contract. The publisher resolves each checkpoint's (chainId, contract) from
// the public grant-store objects — never from deployment-wide UNIVOCITY_* env
// vars (ADR-0034) and never via the operator's univocity HTTP service, so a
// third party can run the same resolution from public data alone.
//
// Layout (public bucket):
//
//	index:   forests/index/forest/{uuid-subject}   -> ASCII UUID of R
//	genesis: forests/forest/{uuid-R}/genesis.cbor  -> chain binding
//
// The semantics mirror the univocity service resolution
// (arbor/services/univocity grant_chain.go resolveForestForLog +
// genesis_parse.go); divergence between the two is guarded by the resolve
// vectors under testdata (ADR-0047 mitigation).

// ErrForestNotResolved indicates no forest binding exists for the log: the
// global index has no entry and the log is not itself a forest root with a
// genesis document.
var ErrForestNotResolved = errors.New("forest not resolved for log")

// ForestContract is a forest's curator-attested chain binding: the bootstrap
// root R and the (chainId, contract) of its univocity instance (ADR-0034).
type ForestContract struct {
	R        logid.UUID
	ChainID  uint64
	Contract common.Address
}

// ObjectGetter reads one object from the public grant-store layout by key. A
// missing object must return an error matching massifstorage.ErrDoesNotExist.
type ObjectGetter interface {
	Get(ctx context.Context, key string) ([]byte, error)
}

// Genesis CBOR map labels (canopy forest-genesis-labels.ts; mirrored by the
// univocity service genesis_labels.go).
const (
	genesisLabelVersion        = -68009
	genesisLabelBootstrapLogID = -68010
	genesisLabelUnivocityAddr  = -68011
	genesisLabelLegacyChainIDs = -68012 // rejected on v1+
	genesisLabelChainID        = -68013
	genesisSchemaVersionMin    = 1
	genesisSchemaVersionMax    = 2
	maxResolveObjectBytes      = 256 * 1024
)

var chainIDDecimalRE = regexp.MustCompile(`^[0-9]{1,10}$`)

// ResolveForestContract resolves the forest chain binding for logID from the
// public store: global index logId -> R (ADR-0036), then the forest genesis
// chain binding (ADR-0034). When the index has no entry the logId is probed
// as a forest root itself (genesis self-indexing is best effort on POST).
func ResolveForestContract(
	ctx context.Context, store ObjectGetter, logID logid.UUID,
) (ForestContract, error) {
	r := logID
	indexed := false
	body, err := store.Get(ctx, "forests/index/forest/"+logID.String())
	switch {
	case err == nil:
		r, err = logid.ParseIndexBody(clampObject(body))
		if err != nil {
			return ForestContract{}, fmt.Errorf("index payload for %s: %w", logID, err)
		}
		indexed = true
	case errors.Is(err, massifstorage.ErrDoesNotExist):
		// Fall through: probe logID as a forest root.
	default:
		return ForestContract{}, fmt.Errorf("read index for %s: %w", logID, err)
	}

	genesis, err := store.Get(ctx, "forests/forest/"+r.String()+"/genesis.cbor")
	if err != nil {
		if errors.Is(err, massifstorage.ErrDoesNotExist) {
			if indexed {
				return ForestContract{}, fmt.Errorf(
					"%w: index maps %s to forest %s but its genesis is missing",
					ErrForestNotResolved, logID, r)
			}
			return ForestContract{}, fmt.Errorf(
				"%w: no index entry for %s and it is not a forest root",
				ErrForestNotResolved, logID)
		}
		return ForestContract{}, fmt.Errorf("read genesis for forest %s: %w", r, err)
	}

	fc, err := parseGenesisChainBinding(clampObject(genesis))
	if err != nil {
		return ForestContract{}, fmt.Errorf("genesis for forest %s: %w", r, err)
	}
	if fc.R != r {
		return ForestContract{}, fmt.Errorf(
			"genesis for forest %s: bootstrap-logid %s does not match object key",
			r, fc.R)
	}
	return fc, nil
}

// parseGenesisChainBinding decodes the chain binding from a v1/v2 forest
// genesis document. Mirrors the univocity service parseGenesisV1.
func parseGenesisChainBinding(body []byte) (ForestContract, error) {
	var top any
	if err := cbor.Unmarshal(body, &top); err != nil {
		return ForestContract{}, fmt.Errorf("decode genesis cbor: %w", err)
	}
	m := intKeyMap(top)
	if m == nil {
		return ForestContract{}, errors.New("genesis body must be a CBOR map")
	}
	if _, ok := m[genesisLabelLegacyChainIDs]; ok {
		return ForestContract{}, errors.New("legacy univocity-chainids not supported")
	}
	version, ok := mapUint(m, genesisLabelVersion)
	if !ok || version < genesisSchemaVersionMin || version > genesisSchemaVersionMax {
		return ForestContract{}, errors.New("genesis-version must be 1 or 2")
	}
	boot, ok := mapBytesN(m, genesisLabelBootstrapLogID, 32)
	if !ok {
		return ForestContract{}, errors.New("bootstrap-logid must be 32 bytes")
	}
	addr, ok := mapBytesN(m, genesisLabelUnivocityAddr, 20)
	if !ok {
		return ForestContract{}, errors.New("univocity-addr must be 20 bytes")
	}
	chainStr, ok := mapString(m, genesisLabelChainID)
	if !ok || !chainIDDecimalRE.MatchString(chainStr) {
		return ForestContract{}, errors.New("chain-id must be decimal EIP-155 string")
	}
	chainID, err := strconv.ParseUint(chainStr, 10, 64)
	if err != nil {
		return ForestContract{}, errors.New("chain-id out of range")
	}
	return ForestContract{
		R:        logid.FromPaddedWire32(boot),
		ChainID:  chainID,
		Contract: common.BytesToAddress(addr),
	}, nil
}

// intKeyMap unwraps cbor.Tag wrappers (cbor-x Map tags) and coerces a CBOR
// map's keys to int.
func intKeyMap(v any) map[int]any {
	for {
		tag, ok := v.(cbor.Tag)
		if !ok {
			break
		}
		v = tag.Content
	}
	raw, ok := v.(map[any]any)
	if !ok {
		return nil
	}
	out := make(map[int]any, len(raw))
	for k, val := range raw {
		switch key := k.(type) {
		case int:
			out[key] = val
		case int64:
			out[int(key)] = val
		case uint64:
			out[int(key)] = val
		default:
			return nil
		}
	}
	return out
}

func mapUint(m map[int]any, label int) (uint64, bool) {
	switch n := m[label].(type) {
	case uint64:
		return n, true
	case uint:
		return uint64(n), true
	case int:
		if n >= 0 {
			return uint64(n), true
		}
	case int64:
		if n >= 0 {
			return uint64(n), true
		}
	}
	return 0, false
}

func mapString(m map[int]any, label int) (string, bool) {
	s, ok := m[label].(string)
	return strings.TrimSpace(s), ok
}

// mapBytesN returns the label's byte-string value when exactly n bytes,
// unwrapping cbor-x tagged byte strings (Uint8Array as tagged bstr).
func mapBytesN(m map[int]any, label, n int) ([]byte, bool) {
	b, ok := asBytes(m[label])
	if !ok || len(b) != n {
		return nil, false
	}
	return b, true
}

func asBytes(v any) ([]byte, bool) {
	switch b := v.(type) {
	case []byte:
		return b, true
	case string:
		return []byte(b), true
	case cbor.Tag:
		return asBytes(b.Content)
	default:
		return nil, false
	}
}

// clampObject bounds store reads to the service's stored-object limit.
func clampObject(b []byte) []byte {
	if len(b) > maxResolveObjectBytes {
		return b[:maxResolveObjectBytes]
	}
	return b
}
