package univocity

import (
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
