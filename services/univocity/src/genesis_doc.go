package univocity

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fxamacker/cbor/v2"
)

// GenesisDoc is a parsed forest genesis document: the forest binding plus the
// genesis (bootstrap/authority) ES256 public key.
type GenesisDoc struct {
	Forest ForestEntry
	KeyX   [32]byte
	KeyY   [32]byte
}

// GenesisKeyBytes returns the 64-byte x||y form of the genesis key, matching the
// on-chain bootstrapConfig() key and root grantData encoding.
func (g GenesisDoc) GenesisKeyBytes() []byte {
	out := make([]byte, 64)
	copy(out[:32], g.KeyX[:])
	copy(out[32:], g.KeyY[:])
	return out
}

// parseGenesisDoc decodes a v1 forest genesis document into its forest binding
// and genesis key. It enforces the same v1 invariants as parseGenesisV1 and
// additionally requires a well-formed EC2/P-256 COSE_Key.
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
	if v, ok := m.uint(labelGenesisVersion); !ok || v != genesisSchemaV1 {
		return GenesisDoc{}, errors.New("genesis-version must be 1")
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
	if kty, ok := m.uint(coseKeyKty); !ok || kty != coseKtyEc2 {
		return GenesisDoc{}, errors.New("genesis COSE_Key must be EC2")
	}
	if crv, ok := m.int(coseEc2Crv); !ok || crv != coseCrvP256 {
		return GenesisDoc{}, errors.New("genesis COSE_Key must use P-256")
	}
	keyX, ok := m.bytes32(coseEc2X)
	if !ok {
		return GenesisDoc{}, errors.New("genesis COSE_Key x must be 32 bytes")
	}
	keyY, ok := m.bytes32(coseEc2Y)
	if !ok {
		return GenesisDoc{}, errors.New("genesis COSE_Key y must be 32 bytes")
	}
	return GenesisDoc{
		Forest: ForestEntry{
			R:        boot,
			ChainID:  chainID,
			Contract: common.BytesToAddress(addr),
		},
		KeyX: keyX,
		KeyY: keyY,
	}, nil
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
