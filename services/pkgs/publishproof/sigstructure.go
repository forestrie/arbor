package publishproof

import (
	"fmt"
)

// DetachedPayload returns the COSE detached payload the contract verifies a
// consistency receipt signature against (ADR-0046 / FOR-321, checkpoint format
// v3): the raw concatenation of the accumulator peaks in descending height
// order — no hashing. This is exactly what univocity
// buildDetachedPayloadCommitment returns, so a signer and the contract sign
// and verify over the same bytes.
func DetachedPayload(accumulator [][32]byte) []byte {
	packed := make([]byte, 0, len(accumulator)*32)
	for _, peak := range accumulator {
		packed = append(packed, peak[:]...)
	}
	return packed
}

// SigStructure returns the COSE Sign1 Sig_structure the contract hashes for
// signature verification (cosecbor.buildSigStructure): a deterministic CBOR
// [ "Signature1", protected, h”, payload ] with no external AAD.
func SigStructure(protectedHeader, payload []byte) []byte {
	out := []byte{0x84}
	out = append(out, 0x6a)
	out = append(out, []byte("Signature1")...)
	out = append(out, cborBstr(protectedHeader)...)
	out = append(out, 0x40)
	out = append(out, cborBstr(payload)...)
	return out
}

// cborBstr encodes a definite-length CBOR byte string header + bytes. Sizes
// beyond 64KiB do not occur in checkpoint material.
func cborBstr(data []byte) []byte {
	n := len(data)
	var head []byte
	switch {
	case n < 24:
		head = []byte{0x40 + byte(n)}
	case n < 256:
		head = []byte{0x58, byte(n)}
	case n < 1<<16:
		head = []byte{0x59, byte(n >> 8), byte(n)}
	default:
		panic(fmt.Sprintf("publishproof: byte string of %d bytes exceeds checkpoint material bounds", n))
	}
	return append(head, data...)
}
