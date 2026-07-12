package delegationcert

import (
	"encoding/hex"
	"testing"
)

// TestCanonicalGolden locks the RFC 8949 §4.2 core-deterministic wire bytes for
// a fixed delegation certificate. The same vector is asserted byte-for-byte by
// the TS @canopy/encoding cross-check (delegation-cose golden test), proving Go
// and TS emit identical canonical COSE for the delegation profile.
//
// Guards status-2607-03 (cbor-x / canonicity): if this changes, TS and Go have
// diverged and delegation-cert signatures will not interoperate.
func TestCanonicalGolden(t *testing.T) {
	kid := make([]byte, 16)
	for i := range kid {
		kid[i] = byte(i)
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	for i := 0; i < 32; i++ {
		x[i] = byte(0x10 + i)
		y[i] = byte(0x40 + i)
	}
	delegationID := make([]byte, 16)
	for i := range delegationID {
		delegationID[i] = byte(0xa0 + i)
	}

	dk, err := NewDelegatedCoseKey(Secp256r1, x, y)
	if err != nil {
		t.Fatal(err)
	}
	input := DelegationInput{
		LogID:        "a1b2c3d4e5f67890abcdef1234567890",
		MmrStart:     0,
		MmrEnd:       63,
		DelegatedKey: dk,
		DelegationID: delegationID,
		IssuedAt:     1000000,
		ExpiresAt:    2000000,
	}

	tbs, err := BuildDelegationToBeSigned(Secp256r1, kid, input)
	if err != nil {
		t.Fatal(err)
	}

	const wantProtected = "a301260378256170706c69636174696f6e2f666f726573747269652e64656c65676174696f6e2b63626f720450000102030405060708090a0b0c0d0e0f"
	const wantPayload = "a90178206131623263336434653566363738393061626364656631323334353637383930030004183f05a401022001215820101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f225820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f06a00701081a000f4240091a001e84800a50a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"

	if got := hex.EncodeToString(tbs.ProtectedBytes); got != wantProtected {
		t.Errorf("protected mismatch:\n got=%s\nwant=%s", got, wantProtected)
	}
	if got := hex.EncodeToString(tbs.PayloadBytes); got != wantPayload {
		t.Errorf("payload mismatch:\n got=%s\nwant=%s", got, wantPayload)
	}
}
