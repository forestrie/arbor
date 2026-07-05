package publishproof

import (
	"fmt"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/fxamacker/cbor/v2"
)

// The format-v3 checkpoint receipt codec lives in go-merklelog massifs. These
// adapters convert between the calldata-shaped [32]byte ConsistencyProof /
// ConsistencyReceipt types publishproof uses for the on-chain ABI and the
// go-merklelog receipt profile ([][]byte nodes).

// EncodeConsistencyProof encodes one consistency proof per draft-bryce
// (`bstr .cbor [tree-size-1, tree-size-2, consistency-paths, right-peaks]`).
func EncodeConsistencyProof(p ConsistencyProof) ([]byte, error) {
	return massifs.EncodeConsistencyProof(toProfileProof(p))
}

// DecodeConsistencyProof reverses EncodeConsistencyProof.
func DecodeConsistencyProof(bstr []byte) (ConsistencyProof, error) {
	m, err := massifs.DecodeConsistencyProof(bstr)
	if err != nil {
		return ConsistencyProof{}, err
	}
	return fromProfileProof(m)
}

// EncodeCheckpointReceipt encodes a format-v3 checkpoint object (COSE Receipt
// of Consistency). Used by tests standing in for the sealer; the sealer itself
// produces receipts via go-merklelog rootsigner.
func EncodeCheckpointReceipt(protectedHeader []byte, proof ConsistencyProof, signature []byte) ([]byte, error) {
	return massifs.EncodeCheckpointReceipt(protectedHeader, toProfileProof(proof), signature)
}

// DecodeCheckpointReceipt decodes a format-v3 checkpoint object into the
// pre-decoded ConsistencyReceipt parts publishCheckpoint takes. When the
// sealer embedded the univocity on-chain delegation proof (Forestrie
// unprotected label, plan-0003 OnchainDelegationProof), it is wired into the
// calldata delegationProof; otherwise the delegation proof is empty
// (root/authority direct-signing path).
func DecodeCheckpointReceipt(data []byte) (ConsistencyReceipt, error) {
	r, err := massifs.DecodeCheckpointReceipt(data)
	if err != nil {
		return ConsistencyReceipt{}, err
	}
	proof, err := fromProfileProof(r.Proof)
	if err != nil {
		return ConsistencyReceipt{}, err
	}
	delegation := DelegationProof{
		ProtectedHeader: []byte{},
		DelegationKey:   []byte{},
		Signature:       []byte{},
	}
	if raw, ok := r.Extras[massifs.SealDelegationProofLabel]; ok {
		var onchain delegationcert.OnchainDelegationProof
		if err := cbor.Unmarshal(raw, &onchain); err != nil {
			return ConsistencyReceipt{}, fmt.Errorf("decode onchain delegation proof: %w", err)
		}
		delegation = DelegationProof{
			ProtectedHeader: onchain.ProtectedHeader,
			DelegationKey:   onchain.DelegationKey,
			MmrStart:        onchain.MMRStart,
			MmrEnd:          onchain.MMREnd,
			Signature:       onchain.Signature,
		}
	}
	return ConsistencyReceipt{
		ProtectedHeader:   r.ProtectedHeader,
		Signature:         r.Signature,
		ConsistencyProofs: []ConsistencyProof{proof},
		DelegationProof:   delegation,
	}, nil
}

func toProfileProof(p ConsistencyProof) massifs.ConsistencyProof {
	mp := massifs.ConsistencyProof{
		TreeSize1:  p.TreeSize1,
		TreeSize2:  p.TreeSize2,
		Paths:      make([][][]byte, len(p.Paths)),
		RightPeaks: make([][]byte, len(p.RightPeaks)),
	}
	for i := range p.Paths {
		mp.Paths[i] = make([][]byte, len(p.Paths[i]))
		for j := range p.Paths[i] {
			mp.Paths[i][j] = p.Paths[i][j][:]
		}
	}
	for i := range p.RightPeaks {
		mp.RightPeaks[i] = p.RightPeaks[i][:]
	}
	return mp
}

func fromProfileProof(m massifs.ConsistencyProof) (ConsistencyProof, error) {
	p := ConsistencyProof{
		TreeSize1:  m.TreeSize1,
		TreeSize2:  m.TreeSize2,
		Paths:      make([][][32]byte, len(m.Paths)),
		RightPeaks: make([][32]byte, len(m.RightPeaks)),
	}
	for i := range m.Paths {
		p.Paths[i] = make([][32]byte, len(m.Paths[i]))
		for j := range m.Paths[i] {
			node, err := toNode32(m.Paths[i][j])
			if err != nil {
				return ConsistencyProof{}, fmt.Errorf("path[%d][%d]: %w", i, j, err)
			}
			p.Paths[i][j] = node
		}
	}
	for i := range m.RightPeaks {
		node, err := toNode32(m.RightPeaks[i])
		if err != nil {
			return ConsistencyProof{}, fmt.Errorf("rightPeaks[%d]: %w", i, err)
		}
		p.RightPeaks[i] = node
	}
	return p, nil
}

func toNode32(b []byte) ([32]byte, error) {
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("node is %d bytes, want 32", len(b))
	}
	return [32]byte(b), nil
}
