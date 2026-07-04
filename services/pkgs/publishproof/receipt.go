package publishproof

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Checkpoint format v3 (ADR-0046): the sealed checkpoint object is a
// draft-bryce COSE Receipt of Consistency. It is a COSE Sign1 with a detached
// payload (the raw-concat accumulator, see DetachedPayload), carrying one
// consistency proof from the previous checkpoint to this seal. A publisher
// decodes it into the pre-decoded ConsistencyReceipt parts the contract's
// publishCheckpoint takes, and chains the proofs from consecutive checkpoints
// into the ConsistencyProof[] calldata when catching up over multiple seals
// (plan-0033 D6: one seal → one proof; the chain is assembled at publish time).
//
// draft-bryce COSE Receipts MMR profile labels:
const (
	// labelVDP is the unprotected-header label carrying the verifiable-proofs
	// map (draft: vdp).
	labelVDP int64 = 396
	// keyConsistencyProof is the verifiable-proofs map key for the single
	// consistency proof this receipt carries (draft: consistency-proof).
	keyConsistencyProof int64 = -2
)

// canonicalCBOR encodes deterministically (RFC 8949 canonical) so encodings
// are stable across producers.
var canonicalCBOR cbor.EncMode

func init() {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("publishproof: canonical cbor mode: %v", err))
	}
	canonicalCBOR = em
}

// cborConsistencyProof is the draft-bryce consistency proof, encoded as a CBOR
// array: [tree-size-1, tree-size-2, consistency-paths, right-peaks].
type cborConsistencyProof struct {
	_          struct{} `cbor:",toarray"`
	TreeSize1  uint64
	TreeSize2  uint64
	Paths      [][][]byte
	RightPeaks [][]byte
}

// EncodeConsistencyProof encodes one consistency proof as the draft's
// `consistency-proof = bstr .cbor [...]`: a CBOR byte string whose content is
// the CBOR array of the four fields.
func EncodeConsistencyProof(p ConsistencyProof) ([]byte, error) {
	cp := cborConsistencyProof{
		TreeSize1:  p.TreeSize1,
		TreeSize2:  p.TreeSize2,
		Paths:      make([][][]byte, len(p.Paths)),
		RightPeaks: make([][]byte, len(p.RightPeaks)),
	}
	for i := range p.Paths {
		cp.Paths[i] = make([][]byte, len(p.Paths[i]))
		for j := range p.Paths[i] {
			cp.Paths[i][j] = p.Paths[i][j][:]
		}
	}
	for i := range p.RightPeaks {
		cp.RightPeaks[i] = p.RightPeaks[i][:]
	}
	inner, err := canonicalCBOR.Marshal(cp)
	if err != nil {
		return nil, fmt.Errorf("encode consistency proof array: %w", err)
	}
	// Wrap the array bytes as a CBOR byte string (`bstr .cbor`).
	bstr, err := canonicalCBOR.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("wrap consistency proof bstr: %w", err)
	}
	return bstr, nil
}

// DecodeConsistencyProof reverses EncodeConsistencyProof.
func DecodeConsistencyProof(bstr []byte) (ConsistencyProof, error) {
	var inner []byte
	if err := cbor.Unmarshal(bstr, &inner); err != nil {
		return ConsistencyProof{}, fmt.Errorf("unwrap consistency proof bstr: %w", err)
	}
	var cp cborConsistencyProof
	if err := cbor.Unmarshal(inner, &cp); err != nil {
		return ConsistencyProof{}, fmt.Errorf("decode consistency proof array: %w", err)
	}
	out := ConsistencyProof{
		TreeSize1:  cp.TreeSize1,
		TreeSize2:  cp.TreeSize2,
		Paths:      make([][][32]byte, len(cp.Paths)),
		RightPeaks: make([][32]byte, len(cp.RightPeaks)),
	}
	for i := range cp.Paths {
		out.Paths[i] = make([][32]byte, len(cp.Paths[i]))
		for j := range cp.Paths[i] {
			node, err := toNode32(cp.Paths[i][j])
			if err != nil {
				return ConsistencyProof{}, fmt.Errorf("path[%d][%d]: %w", i, j, err)
			}
			out.Paths[i][j] = node
		}
	}
	for i := range cp.RightPeaks {
		node, err := toNode32(cp.RightPeaks[i])
		if err != nil {
			return ConsistencyProof{}, fmt.Errorf("rightPeaks[%d]: %w", i, err)
		}
		out.RightPeaks[i] = node
	}
	return out, nil
}

// EncodeCheckpointReceipt encodes a format-v3 checkpoint: a COSE Sign1
// [protected, unprotected, payload, signature] with a detached payload (null)
// and the consistency proof under the unprotected verifiable-proofs map.
// protectedHeader is the sealer's already-CBOR-encoded protected header bytes
// (carried verbatim so the on-chain signature check sees the signed bytes);
// signature is the raw COSE signature over the Sig_structure.
func EncodeCheckpointReceipt(protectedHeader []byte, proof ConsistencyProof, signature []byte) ([]byte, error) {
	proofBstr, err := EncodeConsistencyProof(proof)
	if err != nil {
		return nil, err
	}
	verifiableProofs, err := canonicalCBOR.Marshal(
		map[int64]cbor.RawMessage{keyConsistencyProof: proofBstr},
	)
	if err != nil {
		return nil, fmt.Errorf("encode verifiable-proofs: %w", err)
	}
	unprotected := map[int64]cbor.RawMessage{labelVDP: verifiableProofs}

	// COSE Sign1 = [protected: bstr, unprotected: map, payload: null, sig: bstr]
	sign1 := []any{protectedHeader, unprotected, nil, signature}
	out, err := canonicalCBOR.Marshal(sign1)
	if err != nil {
		return nil, fmt.Errorf("encode checkpoint receipt: %w", err)
	}
	return out, nil
}

// DecodeCheckpointReceipt decodes a format-v3 checkpoint object into the
// pre-decoded ConsistencyReceipt parts publishCheckpoint takes. The delegation
// proof is empty here (root/authority KS256 path); ES256 delegated data-log
// receipts carry it in a Forestrie unprotected label added with the sealer.
func DecodeCheckpointReceipt(data []byte) (ConsistencyReceipt, error) {
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(data, &arr); err != nil {
		return ConsistencyReceipt{}, fmt.Errorf("decode COSE Sign1 array: %w", err)
	}
	if len(arr) != 4 {
		return ConsistencyReceipt{}, fmt.Errorf("COSE Sign1 must have 4 elements, got %d", len(arr))
	}
	var protected []byte
	if err := cbor.Unmarshal(arr[0], &protected); err != nil {
		return ConsistencyReceipt{}, fmt.Errorf("decode protected header: %w", err)
	}
	var unprotected map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(arr[1], &unprotected); err != nil {
		return ConsistencyReceipt{}, fmt.Errorf("decode unprotected header: %w", err)
	}
	var signature []byte
	if err := cbor.Unmarshal(arr[3], &signature); err != nil {
		return ConsistencyReceipt{}, fmt.Errorf("decode signature: %w", err)
	}

	vpRaw, ok := unprotected[labelVDP]
	if !ok {
		return ConsistencyReceipt{}, fmt.Errorf("receipt has no verifiable-proofs (label %d)", labelVDP)
	}
	var vp map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(vpRaw, &vp); err != nil {
		return ConsistencyReceipt{}, fmt.Errorf("decode verifiable-proofs: %w", err)
	}
	proofBstr, ok := vp[keyConsistencyProof]
	if !ok {
		return ConsistencyReceipt{}, fmt.Errorf("verifiable-proofs has no consistency proof (key %d)", keyConsistencyProof)
	}
	proof, err := DecodeConsistencyProof(proofBstr)
	if err != nil {
		return ConsistencyReceipt{}, err
	}
	return ConsistencyReceipt{
		ProtectedHeader:   protected,
		Signature:         signature,
		ConsistencyProofs: []ConsistencyProof{proof},
		DelegationProof: DelegationProof{
			ProtectedHeader: []byte{},
			DelegationKey:   []byte{},
			Signature:       []byte{},
		},
	}, nil
}

func toNode32(b []byte) ([32]byte, error) {
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("node is %d bytes, want 32", len(b))
	}
	return [32]byte(b), nil
}
