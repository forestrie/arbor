package delegationcert

// DelegationIssueRequest is the CBOR body for POST /api/delegations (plan-0003).
//
// Domain, ChainID, ContractAddress are RESERVED for future cryptographic
// binding of chain provenance to delegation material. They are not
// consumed by any signer or verifier today and are marshalled with
// omitempty so issuers and consumers that do not emit them remain
// wire-compatible. See the matching note on sealer's TrustRootResponse:
// the eventual binding direction is open and the chain id / contract
// address may end up embedded in (or derived from) the public log data,
// in which case any verifier obtains them from log data alone and these
// wire fields become redundant.
type DelegationIssueRequest struct {
	Version             uint64 `cbor:"version,omitempty"`
	Domain              string `cbor:"domain,omitempty"`
	ChainID             string `cbor:"chainId,omitempty"`
	ContractAddress     string `cbor:"contractAddress,omitempty"`
	LogID               []byte `cbor:"logId"`
	MMRStart            uint64 `cbor:"mmrStart"`
	MMREnd              uint64 `cbor:"mmrEnd"`
	Algorithm           string `cbor:"algorithm"`
	DelegatedPublicKey  []byte `cbor:"delegatedPublicKey"`
	RequestedTTLSeconds uint64 `cbor:"requestedTtlSeconds"`
	RequestID           []byte `cbor:"requestId,omitempty"`
}

// DelegationIssueResponse is the CBOR response from POST /api/delegations.
type DelegationIssueResponse struct {
	Version     uint64 `cbor:"version,omitempty"`
	IssuedAt    int64  `cbor:"issuedAt"`
	ExpiresAt   int64  `cbor:"expiresAt"`
	Certificate []byte `cbor:"certificate,omitempty"`
	// OnchainProof is the univocity publishCheckpoint delegation material
	// (plan-0003, FOR-314 Outcome B). Omitted by issuers that do not produce
	// it; consumers remain wire-compatible either way.
	OnchainProof *OnchainDelegationProof `cbor:"onchainProof,omitempty"`
}

// OnchainDelegationProof is the pre-decoded univocity DelegationProof
// calldata material (plan-0003): the log root key's signature over the
// contract's delegation Sig_structure, binding the delegated checkpoint
// signing key to (logId, mmrStart, mmrEnd) under the
// "forestrie.univocity.delegation.v1" domain (delegationVerifier.sol).
// ProtectedHeader carries the root key algorithm (label 1: ES256 or KS256);
// DelegationKey is the delegated P-256 public key as 64 bytes x||y.
type OnchainDelegationProof struct {
	ProtectedHeader []byte `cbor:"protectedHeader"`
	DelegationKey   []byte `cbor:"delegationKey"`
	MMRStart        uint64 `cbor:"mmrStart"`
	MMREnd          uint64 `cbor:"mmrEnd"`
	Signature       []byte `cbor:"signature"`
	// AlgData carries the WebAuthn assertion parts when the root signed via
	// a passkey (protected alg ALG_ES256_WEBAUTHN -65800, ADR-0008/ADR-0063):
	// [authenticatorData, clientDataJSON, 16 bytes of packed big-endian
	// challengeIndex||typeIndex], exactly as decodeWebAuthnDelegationAlgData
	// consumes them. Empty for plain ES256/KS256 roots; omitempty keeps
	// their wire encoding byte-identical to the historical 5-field form
	// (the v0.2.0 contract reverts UnexpectedDelegationAlgData on any
	// element a plain alg does not consume).
	AlgData [][]byte `cbor:"algData,omitempty"`
}
