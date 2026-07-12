package ingress

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// canonicalCBOR is the shared RFC 8949 §4.2 core-deterministic CBOR encoder for
// ingress pull/ack request bodies (bytewise key ordering, definite lengths,
// shortest-form). The package-default cbor.Marshal uses SortNone (struct
// declaration order), which is non-conformant per
// status-2607-03-remove-cbor-x-for-scitt-cose-canonicity.
var canonicalCBOR cbor.EncMode

func init() {
	em, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	if err != nil {
		panic(fmt.Errorf("ingress: build canonical CBOR EncMode: %w", err))
	}
	canonicalCBOR = em
}
