package sealer

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// canonicalCBOR is the shared RFC 8949 §4.2 core-deterministic CBOR encoder for
// every wire/checkpoint artifact this service emits (bytewise key ordering,
// definite lengths, shortest-form). The package-default cbor.Marshal uses
// SortNone, which serialises struct fields in declaration order rather than
// §4.2 bytewise order — non-conformant per
// status-2607-03-remove-cbor-x-for-scitt-cose-canonicity.
var canonicalCBOR cbor.EncMode

func init() {
	em, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	if err != nil {
		panic(fmt.Errorf("sealer: build canonical CBOR EncMode: %w", err))
	}
	canonicalCBOR = em
}
