package custodian

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ecdsaDERSignatureToIEEE1363 converts a Cloud KMS–style ASN.1 DER ECDSA signature
// (SEQUENCE of two INTEGERs, Ecdsa-Sig-Value) to IEEE P1363 fixed-width R‖S for COSE Sign1.
// coordWidth is bytes per coordinate (32 for P-256 and secp256k1).
func ecdsaDERSignatureToIEEE1363(der []byte, coordWidth int) ([]byte, error) {
	if coordWidth < 1 {
		return nil, fmt.Errorf("invalid coordWidth %d", coordWidth)
	}
	var sig struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("parse DER ECDSA signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after DER ECDSA signature")
	}
	if sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("invalid DER ECDSA signature: missing r or s")
	}
	rPadded, err := bigIntUnsignedFixedWidth(sig.R, coordWidth)
	if err != nil {
		return nil, fmt.Errorf("r: %w", err)
	}
	sPadded, err := bigIntUnsignedFixedWidth(sig.S, coordWidth)
	if err != nil {
		return nil, fmt.Errorf("s: %w", err)
	}
	out := make([]byte, coordWidth*2)
	copy(out[:coordWidth], rPadded)
	copy(out[coordWidth:], sPadded)
	return out, nil
}

func bigIntUnsignedFixedWidth(n *big.Int, width int) ([]byte, error) {
	if n.Sign() < 0 {
		return nil, fmt.Errorf("negative coordinate")
	}
	b := n.Bytes()
	if len(b) > width {
		return nil, fmt.Errorf("coordinate exceeds %d bytes", width)
	}
	out := make([]byte, width)
	copy(out[width-len(b):], b)
	return out, nil
}
