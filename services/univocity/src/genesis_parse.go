package univocity

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fxamacker/cbor/v2"
)

var chainIDStringRE = regexp.MustCompile(`^[0-9]{1,10}$`)

// parseChainIDString converts a decimal EIP-155 chain id string to uint64.
func parseChainIDString(s string) (uint64, error) {
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("chain-id out of range")
	}
	return id, nil
}

// parseGenesisV1 decodes a v1 forest genesis document from CBOR bytes.
func parseGenesisV1(bytes []byte) (ForestEntry, error) {
	var top interface{}
	if err := cbor.Unmarshal(bytes, &top); err != nil {
		return ForestEntry{}, fmt.Errorf("decode genesis cbor: %w", err)
	}
	m := decodeCBORIntKeyMap(top)
	if m == nil {
		return ForestEntry{}, fmt.Errorf("genesis body must be a CBOR map")
	}
	if m.has(labelUnivocityChainIDs) {
		return ForestEntry{}, fmt.Errorf("legacy univocity-chainids not supported")
	}
	version, ok := m.uint(labelGenesisVersion)
	if !ok || version != genesisSchemaV1 {
		return ForestEntry{}, fmt.Errorf("genesis-version must be 1")
	}
	boot, ok := m.bytes32(labelBootstrapLogID)
	if !ok {
		return ForestEntry{}, fmt.Errorf("bootstrap-logid must be 32 bytes")
	}
	addr, ok := m.bytes20(labelUnivocityAddr)
	if !ok {
		return ForestEntry{}, fmt.Errorf("univocity-addr must be 20 bytes")
	}
	chainStr, ok := m.string(labelChainID)
	if !ok || !chainIDStringRE.MatchString(chainStr) {
		return ForestEntry{}, fmt.Errorf("chain-id must be decimal EIP-155 string")
	}
	chainID, err := strconv.ParseUint(chainStr, 10, 64)
	if err != nil {
		return ForestEntry{}, fmt.Errorf("chain-id out of range")
	}
	return ForestEntry{
		R:        boot,
		ChainID:  chainID,
		Contract: common.BytesToAddress(addr),
	}, nil
}

type genesisIntMap map[int]interface{}

// decodeCBORIntKeyMap unwraps cbor.Tag wrappers (cbor-x Map/Uint8Array tags)
// and decodes a CBOR int-keyed map into genesisIntMap.
func decodeCBORIntKeyMap(v interface{}) genesisIntMap {
	for {
		if tag, ok := v.(cbor.Tag); ok {
			v = tag.Content
			continue
		}
		break
	}
	raw, ok := v.(map[interface{}]interface{})
	if !ok {
		return nil
	}
	return decodeIntKeyMap(raw)
}

func decodeIntKeyMap(raw map[interface{}]interface{}) genesisIntMap {
	out := make(genesisIntMap)
	for k, v := range raw {
		switch key := k.(type) {
		case int:
			out[key] = v
		case int64:
			out[int(key)] = v
		case uint64:
			out[int(key)] = v
		default:
			return nil
		}
	}
	return out
}

func (m genesisIntMap) has(label int) bool {
	_, ok := m[label]
	return ok
}

func (m genesisIntMap) uint(label int) (uint64, bool) {
	v, ok := m[label]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
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

func (m genesisIntMap) string(label int) (string, bool) {
	v, ok := m[label]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return strings.TrimSpace(s), ok
}

func (m genesisIntMap) bytes32(label int) ([32]byte, bool) {
	b, ok := m.byteSlice(label)
	if !ok || len(b) != 32 {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[:], b)
	return out, true
}

func (m genesisIntMap) bytes20(label int) ([]byte, bool) {
	b, ok := m.byteSlice(label)
	if !ok || len(b) != 20 {
		return nil, false
	}
	return b, true
}

func (m genesisIntMap) byteSlice(label int) ([]byte, bool) {
	v, ok := m[label]
	if !ok {
		return nil, false
	}
	return asByteSlice(v)
}

// wireLogIDFromHex64 parses a 64-char hex log id (no 0x) into 32 wire bytes.
func wireLogIDFromHex64(hex64 string) ([32]byte, bool) {
	if len(hex64) != 64 {
		return [32]byte{}, false
	}
	decoded, err := hex.DecodeString(hex64)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[:], decoded)
	return out, true
}

func forestGenesisObjectKey(hex64 string) string {
	return "forest/" + hex64 + "/genesis.cbor"
}

func parseForestKey(key string) (hex64 string, ok bool) {
	const prefix = "forest/"
	const suffix = "/genesis.cbor"
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
		return "", false
	}
	hex64 = strings.TrimPrefix(key, prefix)
	hex64 = strings.TrimSuffix(hex64, suffix)
	if len(hex64) != 64 {
		return "", false
	}
	return hex64, true
}

// ForestEntry is one curator-provisioned forest (R, chain, contract).
type ForestEntry struct {
	R        [32]byte
	ChainID  uint64
	Contract common.Address
}

func logIDHexKey(id [32]byte) string {
	return hex.EncodeToString(id[:])
}
