package sealer

// TrustRootResponse is the plan-0003 CBOR shape returned by
// GET {TRUST_ROOT_URL}/api/logs/{logId}/public-root.
//
// Only logId, alg, x, y are consumed by the verify path today.
//
// ChainID, ContractAddress, Domain are RESERVED for future cryptographic
// binding of chain provenance to log data. They are not consumed by any
// signer or verifier today. The eventual binding direction is open: chain
// id and contract address may end up embedded in (or derived from) the
// public log data, in which case any verifier obtains them from log data
// alone and these wire fields become redundant. They are decoded as
// omitempty so a trust-root proxy that does not emit them remains
// wire-compatible.
//
// Freshness and block-context fields (blockNumber, blockHash, finality)
// will be added when the Univocity trust-root adapter lands; the CBOR
// decoder will tolerate their absence today and accept them tomorrow.
type TrustRootResponse struct {
	LogID           []byte `cbor:"logId"`
	Alg             string `cbor:"alg"`
	X               []byte `cbor:"x"`
	Y               []byte `cbor:"y"`
	Key             []byte `cbor:"key,omitempty"`
	ChainID         string `cbor:"chainId,omitempty"`
	ContractAddress string `cbor:"contractAddress,omitempty"`
	Domain          string `cbor:"domain,omitempty"`
}
