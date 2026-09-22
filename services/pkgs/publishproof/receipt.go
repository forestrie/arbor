package publishproof

import (
	"errors"
	"fmt"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/fxamacker/cbor/v2"
)

// ErrSignedSizeMismatch indicates a checkpoint receipt's signed tree-size-2
// (ADR-0066 protected header label -65933) does not match the sealed size
// its consistency proof chain reaches, or that the protected header does not
// carry the label at all (signed before ADR-0066). See CheckSignedSize.
var ErrSignedSizeMismatch = errors.New("signed tree-size-2 does not match the declared proof chain")

// CheckSignedSize verifies a checkpoint receipt's signed tree-size-2 against
// the last link of its consistency proof chain: the size the contract will
// store and the accumulator the signature covers must be read at the same
// height, otherwise the same signed calldata is accepted at every size with
// the same peak count (ADR-0066).
//
// Only tree-size-2 is signed. Each link's tree-size-1 is unsigned prover
// context: the contract binds the first link's base to its own stored size
// and each later link's base to the previous link's target, so the publisher
// is free to relay embedded per-seal proofs or to rebuild the head segment
// from the on-chain size (BuildEmbeddedProofChain) under the head
// checkpoint's original signature.
//
// A mismatch means the receipt was assembled for a different sealed size
// than the one the sealer signed and would fail the same check on-chain
// (ConsistencyReceiptSizeMismatch); a header without the label fails the way
// the contract's MissingSignedTreeSize does.
func CheckSignedSize(receipt ConsistencyReceipt) error {
	if len(receipt.ConsistencyProofs) == 0 {
		return fmt.Errorf("%w: no consistency proofs", ErrSignedSizeMismatch)
	}
	signed, err := massifs.ProtectedHeaderTreeSize(receipt.ProtectedHeader)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignedSizeMismatch, err)
	}
	last := receipt.ConsistencyProofs[len(receipt.ConsistencyProofs)-1]
	if signed != last.TreeSize2 {
		return fmt.Errorf("%w: signed tree-size-2 %d != chain tree-size-2 %d",
			ErrSignedSizeMismatch, signed, last.TreeSize2)
	}
	return nil
}

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
// of Consistency) carrying a single consistency proof. Used by tests standing
// in for the sealer; the sealer itself produces receipts via go-merklelog
// rootsigner. The single proof is written as the draft's
// `consistency-proofs = [ + consistency-proof ]`, an array of one.
func EncodeCheckpointReceipt(protectedHeader []byte, proof ConsistencyProof, signature []byte) ([]byte, error) {
	return massifs.EncodeCheckpointReceipt(protectedHeader, toProfileProof(proof), signature)
}

// EncodeCheckpointReceiptChain encodes a format-v3 checkpoint object carrying
// a chain of consistency proofs in fold order: the first starts at the size
// its consumer already trusts and each later one at its predecessor's
// tree-size-2, the last of which is the size protectedHeader signs. It is the
// receipt form of the publisher's catch-up: one signature over the head
// accumulator, one proof per sealed step relayed beneath it.
func EncodeCheckpointReceiptChain(
	protectedHeader []byte, proofs []ConsistencyProof, signature []byte,
	extraUnprotected ...map[int64]cbor.RawMessage,
) ([]byte, error) {
	profile := make([]massifs.ConsistencyProof, len(proofs))
	for i := range proofs {
		profile[i] = toProfileProof(proofs[i])
	}
	return massifs.EncodeCheckpointReceiptChain(
		protectedHeader, profile, signature, extraUnprotected...)
}

// EncodeChainReceipt re-encodes a stored checkpoint object as the relay
// artefact a catch-up publish is derived from: the head checkpoint's signed
// parts - the protected header and signature, which cover the head
// accumulator and its tree-size-2 (ADR-0046, ADR-0066) - with the relayed
// chain in place of the single embedded proof, and the head's unprotected
// material (delegation proof, pre-signed peak receipts) carried over
// verbatim. Nothing signed is rebuilt: the chain's intermediate sizes are
// unsigned prover context, pinned by the consumer's own trusted size
// (ADR-0066 D2, D5), which for publishCheckpoint is the contract's stored
// size.
//
// DecodeCheckpointReceipt reverses it into exactly the ConsistencyReceipt the
// calldata is packed from, so the submission has one source rather than a
// receipt for the signature and a separately assembled chain for the proofs.
func EncodeChainReceipt(headCheckpoint []byte, chain []ConsistencyProof) ([]byte, error) {
	head, err := massifs.DecodeCheckpointReceipt(headCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("decode head checkpoint: %w", err)
	}
	if err := CheckProofChainContiguous(chain); err != nil {
		return nil, err
	}
	extras := map[int64]cbor.RawMessage{}
	for label, value := range head.Extras {
		extras[label] = value
	}
	// The massifs decoder lifts the peak receipts out of the unprotected
	// header into their own field; put them back so the relay object is the
	// head receipt with its chain extended, not a lossy copy of it.
	if len(head.PeakReceipts) > 0 {
		encoded, err := canonicalReceiptCBOR.Marshal(head.PeakReceipts)
		if err != nil {
			return nil, fmt.Errorf("encode peak receipts: %w", err)
		}
		extras[massifs.SealPeakReceiptsLabel] = encoded
	}
	if len(extras) == 0 {
		return EncodeCheckpointReceiptChain(head.ProtectedHeader, chain, head.Signature)
	}
	return EncodeCheckpointReceiptChain(head.ProtectedHeader, chain, head.Signature, extras)
}

// CheckProofChainContiguous requires each link of a relayed chain to start
// where its predecessor ends. The intermediate sizes carry no signature, so
// this comparison is the only thing joining the links: a gap or an overlap
// would present two unrelated extensions as one catch-up. The contract
// (verifyConsistencyProofChain) and the go-merklelog verifier both reject
// such a chain, so it is rejected here rather than encoded into a receipt
// nothing will accept; the error matches massifs.ErrProofChainNotContiguous.
func CheckProofChainContiguous(chain []ConsistencyProof) error {
	if len(chain) == 0 {
		return massifs.ErrProofChainEmpty
	}
	for i := 1; i < len(chain); i++ {
		if chain[i].TreeSize1 != chain[i-1].TreeSize2 {
			return fmt.Errorf("%w: proof %d starts at size %d, proof %d ends at size %d",
				massifs.ErrProofChainNotContiguous,
				i, chain[i].TreeSize1, i-1, chain[i-1].TreeSize2)
		}
	}
	return nil
}

// canonicalReceiptCBOR matches the encoding go-merklelog writes checkpoint
// material with, so a re-encoded unprotected value is byte-identical to the
// one the sealer wrote.
var canonicalReceiptCBOR = func() cbor.EncMode {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("publishproof: canonical cbor mode: %v", err))
	}
	return em
}()

// DecodeCheckpointReceipt decodes a format-v3 checkpoint object into the
// pre-decoded ConsistencyReceipt parts publishCheckpoint takes. Every
// consistency proof the object carries becomes one element of the calldata
// chain, in order, so a single-proof seal and a relayed chain
// (EncodeChainReceipt) both decode into the submission they describe.
//
// When the sealer embedded the univocity on-chain delegation proof (Forestrie
// unprotected label, plan-0003 OnchainDelegationProof), it is wired into the
// calldata delegationProof; otherwise the delegation proof is empty
// (root/authority direct-signing path).
func DecodeCheckpointReceipt(data []byte) (ConsistencyReceipt, error) {
	r, err := massifs.DecodeCheckpointReceipt(data)
	if err != nil {
		return ConsistencyReceipt{}, err
	}
	// A sealer-written checkpoint carries one proof; a relay receipt carries
	// the whole chain, which is what the contract's consistencyProofs[] is.
	// Both decode the same way - the last link is the one the protected
	// header signs (CheckSignedSize).
	proofs := make([]ConsistencyProof, len(r.Proofs))
	for i := range r.Proofs {
		proof, err := fromProfileProof(r.Proofs[i])
		if err != nil {
			return ConsistencyReceipt{}, fmt.Errorf("consistency proof %d: %w", i, err)
		}
		proofs[i] = proof
	}
	delegation := DelegationProof{
		ProtectedHeader: []byte{},
		DelegationKey:   []byte{},
		Signature:       []byte{},
		AlgData:         [][]byte{},
	}
	if raw, ok := r.Extras[massifs.SealDelegationProofLabel]; ok {
		var onchain delegationcert.OnchainDelegationProof
		if err := cbor.Unmarshal(raw, &onchain); err != nil {
			return ConsistencyReceipt{}, fmt.Errorf("decode onchain delegation proof: %w", err)
		}
		// Lift algData (WebAuthn assertion parts, ADR-0008/ADR-0063) from
		// the CBOR proof into the calldata. Plain ES256/KS256 proofs omit
		// the field, decoding to nil — normalize to empty, which those algs
		// require (the contract fails closed on stray elements).
		algData := onchain.AlgData
		if algData == nil {
			algData = [][]byte{}
		}
		delegation = DelegationProof{
			ProtectedHeader: onchain.ProtectedHeader,
			DelegationKey:   onchain.DelegationKey,
			MmrStart:        onchain.MMRStart,
			MmrEnd:          onchain.MMREnd,
			Signature:       onchain.Signature,
			AlgData:         algData,
		}
	}
	return ConsistencyReceipt{
		ProtectedHeader:   r.ProtectedHeader,
		Signature:         r.Signature,
		ConsistencyProofs: proofs,
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
