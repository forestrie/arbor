package publishproof

import "github.com/forestrie/go-merklelog/massifs"

// The format-v3 receipt profile (detached payload, COSE Sig_structure, and the
// checkpoint receipt CBOR) lives in go-merklelog massifs — the single source
// shared by the sealer (producer) and the verify/replicate consumers. These
// are thin adapters over the calldata-shaped [32]byte types publishproof uses
// for the on-chain ABI.

// DetachedPayload returns the COSE detached payload the contract verifies a
// consistency receipt signature against: the raw concatenation of the
// accumulator peaks (ADR-0046 / FOR-321).
func DetachedPayload(accumulator [][32]byte) []byte {
	return massifs.DetachedPayload(nodesFrom32(accumulator))
}

// SigStructure returns the COSE Sign1 Sig_structure the signature is over.
func SigStructure(protectedHeader, payload []byte) []byte {
	return massifs.SigStructure(protectedHeader, payload)
}

func nodesFrom32(acc [][32]byte) [][]byte {
	out := make([][]byte, len(acc))
	for i := range acc {
		out[i] = acc[i][:]
	}
	return out
}
