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
}
