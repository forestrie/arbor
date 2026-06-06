package univocity

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/fxamacker/cbor/v2"
)

// GenesisDoc is a parsed forest genesis document: the forest binding plus the
// bootstrap/authority root identity as (alg, opaque key).
type GenesisDoc struct {
	Forest ForestEntry
	Alg    int64
	Key    []byte // opaque: 64 bytes ES256 x||y or 20-byte KS256 address
}

// GenesisKeyBytes returns the opaque bootstrap key bytes (20 or 64), matching
// on-chain bootstrapConfig().bootstrapKey and root grantData encoding.
func (g GenesisDoc) GenesisKeyBytes() []byte {
	out := make([]byte, len(g.Key))
	copy(out, g.Key)
	return out
}

// parseGenesisDoc decodes a v1 forest genesis document into its forest binding
// and bootstrap identity. It accepts either v2 opaque (bootstrap-alg,
// bootstrap-key) labels or the legacy v1 EC2/P-256 COSE_Key map.
func parseGenesisDoc(body []byte) (GenesisDoc, error) {
	var top interface{}
	if err := cbor.Unmarshal(body, &top); err != nil {
		return GenesisDoc{}, errors.New("decode genesis cbor")
	}
	m := decodeCBORIntKeyMap(top)
	if m == nil {
		return GenesisDoc{}, errors.New("genesis body must be a CBOR map")
	}
	if m.has(labelUnivocityChainIDs) {
		return GenesisDoc{}, errors.New("legacy univocity-chainids not supported")
	}
	if v, ok := m.uint(labelGenesisVersion); !ok || !validGenesisSchemaVersion(v) {
		return GenesisDoc{}, errors.New("genesis-version must be 1 or 2")
	}
	boot, ok := m.bytes32(labelBootstrapLogID)
	if !ok {
		return GenesisDoc{}, errors.New("bootstrap-logid must be 32 bytes")
	}
	addr, ok := m.bytes20(labelUnivocityAddr)
	if !ok {
		return GenesisDoc{}, errors.New("univocity-addr must be 20 bytes")
	}
	chainStr, ok := m.string(labelChainID)
	if !ok || !chainIDStringRE.MatchString(chainStr) {
		return GenesisDoc{}, errors.New("chain-id must be a decimal EIP-155 string")
	}
	chainID, err := parseChainIDString(chainStr)
	if err != nil {
		return GenesisDoc{}, err
	}
	forest := ForestEntry{
		R:        logid.FromPaddedWire32(boot[:]),
		ChainID:  chainID,
		Contract: common.BytesToAddress(addr),
	}

	if alg, key, ok, err := parseOpaqueBootstrapKey(m); ok {
		if err != nil {
			return GenesisDoc{}, err
		}
		return GenesisDoc{Forest: forest, Alg: alg, Key: key}, nil
	}
	alg, key, err := parseLegacyES256GenesisKey(m)
	if err != nil {
		return GenesisDoc{}, err
	}
	return GenesisDoc{Forest: forest, Alg: alg, Key: key}, nil
}

func parseOpaqueBootstrapKey(m genesisIntMap) (alg int64, key []byte, ok bool, err error) {
	algVal, hasAlg := m.int(labelBootstrapAlg)
	keyBytes, hasKey := m.byteSlice(labelBootstrapKey)
	if !hasAlg && !hasKey {
		return 0, nil, false, nil
	}
	if !hasAlg || !hasKey {
		return 0, nil, true, errors.New("bootstrap-alg and bootstrap-key must both be present")
	}
	if err := validateBootstrapIdentity(algVal, keyBytes); err != nil {
		return 0, nil, true, err
	}
	out := make([]byte, len(keyBytes))
	copy(out, keyBytes)
	return algVal, out, true, nil
}

func parseLegacyES256GenesisKey(m genesisIntMap) (int64, []byte, error) {
	if kty, ok := m.uint(coseKeyKty); !ok || kty != coseKtyEc2 {
		return 0, nil, errors.New("genesis COSE_Key must be EC2")
	}
	if crv, ok := m.int(coseEc2Crv); !ok || crv != coseCrvP256 {
		return 0, nil, errors.New("genesis COSE_Key must use P-256")
	}
	keyX, ok := m.bytes32(coseEc2X)
	if !ok {
		return 0, nil, errors.New("genesis COSE_Key x must be 32 bytes")
	}
	keyY, ok := m.bytes32(coseEc2Y)
	if !ok {
		return 0, nil, errors.New("genesis COSE_Key y must be 32 bytes")
	}
	out := make([]byte, 64)
	copy(out[:32], keyX[:])
	copy(out[32:], keyY[:])
	return coseAlgES256, out, nil
}

func validateBootstrapIdentity(alg int64, key []byte) error {
	switch alg {
	case coseAlgES256:
		if len(key) != 64 {
			return fmt.Errorf("ES256 bootstrap-key must be 64 bytes, got %d", len(key))
		}
	case coseAlgKS256:
		if len(key) != 20 {
			return fmt.Errorf("KS256 bootstrap-key must be 20 bytes, got %d", len(key))
		}
	default:
		return fmt.Errorf("unsupported bootstrap alg %d", alg)
	}
	return nil
}

// int reads a (possibly negative) integer CBOR value at label.
func (m genesisIntMap) int(label int) (int64, bool) {
	v, ok := m[label]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case uint64:
		return int64(n), true
	}
	return 0, false
}
