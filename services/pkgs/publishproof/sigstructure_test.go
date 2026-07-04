package publishproof

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// The contract (cosecbor.buildSigStructure) verifies receipt signatures over
// Sig_structure = [ "Signature1", protected, external_aad = h”, payload ]
// with the detached payload being the raw concatenation of the final
// accumulator peaks (ADR-0046 / FOR-321). Expected bytes are hand-assembled
// from RFC 9052 deterministic CBOR.
func TestSigStructureOverRawConcatPayload(t *testing.T) {
	protected := mustHex(t, "a1013a00010106") // {1: -65799} (KS256)
	peak := bytes32FromLow(t, "11")

	// Single-peak accumulator: the detached payload is the raw peak.
	payload := DetachedPayload([][32]byte{peak})
	require.Equal(t, peak[:], payload)

	got := SigStructure(protected, payload)

	expected := "84" + // array(4)
		"6a" + hex.EncodeToString([]byte("Signature1")) + // text(10)
		"47" + "a1013a00010106" + // bstr(7) protected
		"40" + // bstr(0) external_aad
		"5820" + hex.EncodeToString(payload) // bstr(32) payload
	require.Equal(t, expected, hex.EncodeToString(got))
}

// The detached payload is the concatenation of the peaks, in order, no hashing.
func TestDetachedPayloadPacksAllPeaks(t *testing.T) {
	p1 := bytes32FromLow(t, "11")
	p2 := bytes32FromLow(t, "22")
	want := append(append([]byte{}, p1[:]...), p2[:]...)
	require.Equal(t, want, DetachedPayload([][32]byte{p1, p2}))
	require.Len(t, DetachedPayload([][32]byte{p1, p2}), 64)
}
