package delegationcert

import (
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// OnchainDelegationDomain is the univocity delegation domain separator
// (delegationVerifier.sol DELEGATION_DOMAIN).
const OnchainDelegationDomain = "forestrie.univocity.delegation.v1"

// es256ProtectedHeader is the canonical CBOR protected header {1: -7} the
// contract reads the root algorithm from (extractAlgorithm).
var es256ProtectedHeader = []byte{0xa1, 0x01, 0x26}

// LogID32FromHex returns the univocity bytes32 log id for a 32-char hex
// forestrie log id: the 16 id bytes right-aligned (low bytes) of the word,
// matching the publishGrant logId the contract compares against.
func LogID32FromHex(logIdHex string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(logIdHex)
	if err != nil {
		return out, fmt.Errorf("log id hex: %w", err)
	}
	if len(b) != 16 {
		return out, fmt.Errorf("log id must be 16 bytes, got %d", len(b))
	}
	copy(out[32-len(b):], b)
	return out, nil
}

// OnchainDelegationToBeSigned holds the material an issuer's root key signs
// to produce the univocity on-chain delegation proof, plus the pre-decoded
// parts of the resulting OnchainDelegationProof.
type OnchainDelegationToBeSigned struct {
	// ProtectedHeader is the CBOR protected header carrying the root key
	// algorithm ({1: -7} for an ES256 root).
	ProtectedHeader []byte
	// SigStructure is the COSE Sig_structure over the contract's packed
	// delegation payload (domain, logId, mmrStart, mmrEnd, delegatedKey).
	// An ES256 root signs its SHA-256 digest; a KS256 root its Keccak-256.
	SigStructure []byte
	// DelegationKey is the delegated P-256 public key as 64 bytes x||y, as
	// the contract decodes it (decodeDelegationKeyES256).
	DelegationKey []byte
}

// BuildOnchainDelegationToBeSigned constructs the signing material for the
// univocity on-chain delegation proof (delegationVerifier.sol): the root key
// authorizes the delegated ES256 checkpoint signing key for [mmrStart,
// mmrEnd] on the log. The returned Sig_structure byte-matches the contract's
// buildSigStructure over abi.encodePacked(domain, logId, mmrStart, mmrEnd,
// keyX, keyY).
func BuildOnchainDelegationToBeSigned(
	logIdHex string, mmrStart, mmrEnd uint64, delegated *DelegatedCoseKey,
) (*OnchainDelegationToBeSigned, error) {
	if delegated == nil {
		return nil, fmt.Errorf("delegated key is required")
	}
	if len(delegated.X) != 32 || len(delegated.Y) != 32 {
		return nil, fmt.Errorf("delegated key coordinates must be 32 bytes each")
	}
	logID32, err := LogID32FromHex(logIdHex)
	if err != nil {
		return nil, err
	}

	payload := make([]byte, 0, len(OnchainDelegationDomain)+32+8+8+64)
	payload = append(payload, OnchainDelegationDomain...)
	payload = append(payload, logID32[:]...)
	payload = binary.BigEndian.AppendUint64(payload, mmrStart)
	payload = binary.BigEndian.AppendUint64(payload, mmrEnd)
	payload = append(payload, delegated.X...)
	payload = append(payload, delegated.Y...)

	sigStructure, err := cbor.Marshal([]any{
		"Signature1",
		es256ProtectedHeader,
		[]byte{}, // external_aad (empty)
		payload,
	})
	if err != nil {
		return nil, fmt.Errorf("encode sig structure: %w", err)
	}

	delegationKey := make([]byte, 0, 64)
	delegationKey = append(delegationKey, delegated.X...)
	delegationKey = append(delegationKey, delegated.Y...)

	return &OnchainDelegationToBeSigned{
		ProtectedHeader: es256ProtectedHeader,
		SigStructure:    sigStructure,
		DelegationKey:   delegationKey,
	}, nil
}

// AssembleOnchainDelegationProof combines the to-be-signed material with the
// root key's raw signature (IEEE P1363 r||s, 64 bytes for ES256) into the
// wire OnchainDelegationProof. The signature is normalized to low-s form:
// the on-chain P256 verifier rejects malleable high-s signatures and ECDSA
// backends (KMS) make no low-s guarantee.
func AssembleOnchainDelegationProof(
	tbs *OnchainDelegationToBeSigned, mmrStart, mmrEnd uint64, signatureRaw []byte,
) (*OnchainDelegationProof, error) {
	if tbs == nil {
		return nil, fmt.Errorf("to-be-signed material is required")
	}
	if len(signatureRaw) != 64 {
		return nil, fmt.Errorf("signature must be 64 bytes (IEEE P1363 r||s)")
	}
	return &OnchainDelegationProof{
		ProtectedHeader: tbs.ProtectedHeader,
		DelegationKey:   tbs.DelegationKey,
		MMRStart:        mmrStart,
		MMREnd:          mmrEnd,
		Signature:       NormalizeES256SignatureLowS(signatureRaw),
	}, nil
}

var (
	p256N     = elliptic.P256().Params().N
	p256HalfN = new(big.Int).Rsh(elliptic.P256().Params().N, 1)
)

// NormalizeES256SignatureLowS returns the low-s form of a raw 64-byte P-256
// signature: (r, N-s) verifies for exactly the same digest and key. Inputs
// that are not 64 bytes are returned unchanged.
func NormalizeES256SignatureLowS(sig []byte) []byte {
	if len(sig) != 64 {
		return sig
	}
	s := new(big.Int).SetBytes(sig[32:])
	if s.Cmp(p256HalfN) <= 0 {
		return sig
	}
	s.Sub(p256N, s)
	out := make([]byte, 64)
	copy(out, sig[:32])
	s.FillBytes(out[32:])
	return out
}

// isLowS reports whether a raw 64-byte P-256 signature is in low-s form.
//
// Verifiers must reject the high-s twin rather than normalise it: (r, s)
// and (r, N-s) both verify for the same digest and key, so accepting both
// makes a signature malleable — the same authorisation with two distinct
// byte encodings. Signature bytes are committed elsewhere in this system,
// so that matters beyond tidiness.
func isLowS(sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	s := new(big.Int).SetBytes(sig[32:])
	return s.Sign() > 0 && s.Cmp(p256HalfN) <= 0
}
