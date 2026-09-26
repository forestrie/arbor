package delegationcert

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestDelegationIssueRequest_HeldPublicKeyHashesWire: the field is omitted on
// the wire when empty (on-demand sealers and coordinators that predate FOR-586
// see an unchanged request) and carried verbatim when set.
func TestDelegationIssueRequest_HeldPublicKeyHashesWire(t *testing.T) {
	base := DelegationIssueRequest{LogID: []byte{1}, Algorithm: "ES256", DelegatedPublicKey: []byte{2}}
	raw, err := cbor.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := cbor.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, present := m["heldPublicKeyHashes"]; present {
		t.Fatal("empty heldPublicKeyHashes must be omitted")
	}
	base.HeldPublicKeyHashes = []string{"aa", "bb"}
	raw, err = cbor.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var back DelegationIssueRequest
	if err := cbor.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.HeldPublicKeyHashes) != 2 || back.HeldPublicKeyHashes[1] != "bb" {
		t.Fatalf("round trip = %v", back.HeldPublicKeyHashes)
	}
}
