package custodian

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var (
	custodianCBORem cbor.EncMode
	custodianCBORdm cbor.DecMode
)

func init() {
	// RFC 8949 §4.2 core-deterministic (bytewise key order), NOT the legacy
	// RFC 7049 length-first CanonicalEncOptions — custodian response structs are
	// string-keyed, where the two orderings genuinely differ. Matches canopy +
	// the rest of arbor (status-2607-03-remove-cbor-x-for-scitt-cose-canonicity).
	em, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	if err != nil {
		panic(fmt.Errorf("custodian cbor enc mode: %w", err))
	}
	dm, err := cbor.DecOptions{
		MaxArrayElements: 1024,
		MaxMapPairs:      256,
	}.DecMode()
	if err != nil {
		panic(fmt.Errorf("custodian cbor dec mode: %w", err))
	}
	custodianCBORem = em
	custodianCBORdm = dm
}
