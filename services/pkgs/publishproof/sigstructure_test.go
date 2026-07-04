package publishproof

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// The contract (cosecbor.buildSigStructure) verifies receipt signatures over
// Sig_structure = [ "Signature1", protected, external_aad = h”, payload ]
// with the detached payload being sha256 of the packed final accumulator.
// Expected bytes are hand-assembled from RFC 9052 deterministic CBOR.
func TestSigStructureMatchesContractCBOR(t *testing.T) {
	protected := mustHex(t, "a1013a00010106") // {1: -65799} (KS256)
	peak := bytes32FromLow(t, "11")

	commitment := ConsistencyCommitment([][32]byte{peak})
	require.Equal(t, sha256.Sum256(peak[:]), commitment)

	got := SigStructure(protected, commitment[:])

	expected := "84" + // array(4)
		"6a" + hex.EncodeToString([]byte("Signature1")) + // text(10)
		"47" + "a1013a00010106" + // bstr(7) protected
		"40" + // bstr(0) external_aad
		"5820" + hex.EncodeToString(commitment[:]) // bstr(32) payload
	require.Equal(t, expected, hex.EncodeToString(got))
}

// Multi-peak accumulators are committed as the concatenation of the peaks.
func TestConsistencyCommitmentPacksAllPeaks(t *testing.T) {
	p1 := bytes32FromLow(t, "11")
	p2 := bytes32FromLow(t, "22")
	want := sha256.Sum256(append(p1[:], p2[:]...))
	require.Equal(t, want, ConsistencyCommitment([][32]byte{p1, p2}))
}
