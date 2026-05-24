package delegationcert

// DelegationIssueRequest is the CBOR body for POST /api/delegations (plan-0003).
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
