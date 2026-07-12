package univocity

import "github.com/fxamacker/cbor/v2"

// canonicalCBOR is the single CBOR encoder for every wire artifact this service
// emits. It enforces RFC 8949 §4.2 core-deterministic encoding (bytewise map/
// struct key ordering, definite lengths, shortest-form) — the strict COSE/SCITT
// canonical profile shared with canopy's @canopy/encoding writer and the rest of
// arbor. The package-default cbor.Marshal uses SortNone, which serialises Go
// maps in random order and struct fields in declaration order — both
// non-conformant. See status-2607-03-remove-cbor-x-for-scitt-cose-canonicity.
var canonicalCBOR cbor.EncMode

func init() {
	em, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	if err != nil {
		panic("univocity: build canonical CBOR EncMode: " + err.Error())
	}
	canonicalCBOR = em
}
