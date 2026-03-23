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
	em, err := cbor.CanonicalEncOptions().EncMode()
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
