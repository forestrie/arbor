package univocity

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fxamacker/cbor/v2"
)

func TestParseGenesisV1(t *testing.T) {
	root := [32]byte{0: 0xaa}
	addr := make([]byte, 20)
	addr[19] = 0x01
	m := map[int]interface{}{
		labelGenesisVersion: genesisSchemaV1,
		labelBootstrapLogID: root[:],
		labelUnivocityAddr:  addr,
		labelChainID:        "84532",
	}
	body, err := cbor.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := parseGenesisV1(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if entry.R != root || entry.ChainID != 84532 {
		t.Fatalf("unexpected entry %+v", entry)
	}
	if entry.Contract != common.BytesToAddress(addr) {
		t.Fatalf("contract mismatch %s", entry.Contract.Hex())
	}
}

// cbor-x (canopy) tags Uint8Array map values; genesis POST bodies must still parse.
func TestParseGenesisV1_cborXTaggedByteStrings(t *testing.T) {
	const hexBody = "d90103a90102200121d84058203a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a22d84058204b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b03263a000109a8013a000109aad84054abababababababababababababababababababab3a000109ac6538343533323a000109a9d840582000000000000000000000000000000000aeacb6e77e8c47de8ea3f0289d203dba"
	body, err := hex.DecodeString(hexBody)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := parseGenesisV1(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if entry.ChainID != 84532 {
		t.Fatalf("chainId: got %d", entry.ChainID)
	}
	if entry.R[16] != 0xae || entry.R[31] != 0xba {
		t.Fatalf("bootstrap wire uuid mismatch: %x", entry.R[16:])
	}
	_, err = parseGenesisDoc(body)
	if err != nil {
		t.Fatalf("parseGenesisDoc: %v", err)
	}
	_ = common.BytesToAddress(entry.Contract[:])
}
