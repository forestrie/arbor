package sealer

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// DelegateKeyVoucher is the custodian's registrar voucher for one standing
// delegate key, returned beside its seed by delegate-seed apiVersion 3
// (devdocs plan-2609-12 slice 07). The sealer holds it in memory only and
// presents it when it asserts the key's registration (slice 05).
//
// The sealer does not verify the signature: it holds no registrar key, and
// the coordinator verifies every voucher it is given (canopy
// delegation-coordinator handlers/post-delegate-keys.ts). The claims are
// decoded to refuse a voucher for another key, sealer or epoch, and to read
// claim 4, which the registration body carries as notAfter.
type DelegateKeyVoucher struct {
	// Raw is the untagged COSE_Sign1, as the custodian signed it.
	Raw      []byte
	SealerID string
	Epoch    uint32
	// CoseKey is the canonical COSE_Key the voucher binds (claim 3).
	CoseKey []byte
	// NotAfter is claim 4: the voucher is not valid at or after it.
	NotAfter time.Time
}

// delegateKeyVoucherClaims is the voucher's int-keyed CBOR payload. Wire
// owner: arbor services/custodian/src/voucher.go (voucherClaimsWire) and
// canopy @forestrie/encoding verify-delegate-key-voucher.ts.
type delegateKeyVoucherClaims struct {
	SealerID string `cbor:"1,keyasint"`
	Epoch    uint32 `cbor:"2,keyasint"`
	Key      []byte `cbor:"3,keyasint"`
	NotAfter uint64 `cbor:"4,keyasint,omitempty"`
}

// decodeDelegateKeyVoucher decodes a voucher's claims. A voucher without
// claim 4 is refused: apiVersion 3 vouchers always carry it.
func decodeDelegateKeyVoucher(raw []byte) (*DelegateKeyVoucher, error) {
	var msg cose.UntaggedSign1Message
	if err := msg.UnmarshalCBOR(raw); err != nil {
		return nil, fmt.Errorf("decode voucher: %w", err)
	}
	var c delegateKeyVoucherClaims
	if err := cbor.Unmarshal(msg.Payload, &c); err != nil {
		return nil, fmt.Errorf("decode voucher claims: %w", err)
	}
	if c.NotAfter == 0 {
		return nil, fmt.Errorf("voucher has no notAfter (claim 4)")
	}
	return &DelegateKeyVoucher{
		Raw:      raw,
		SealerID: c.SealerID,
		Epoch:    c.Epoch,
		CoseKey:  c.Key,
		NotAfter: time.Unix(int64(c.NotAfter), 0),
	}, nil
}
