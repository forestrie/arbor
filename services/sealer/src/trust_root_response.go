package sealer

// TrustRootResponse is the plan-0003 CBOR shape returned by
// GET {TRUST_ROOT_URL}/api/logs/{logId}/signing-key.
//
// Only the fields required for the BYOK lease verify path are populated in
// this step. Freshness and block-context fields (blockNumber, blockHash,
// finality) will be added when the Univocity trust-root adapter lands; the
// CBOR decoder will tolerate their absence today and accept them tomorrow.
type TrustRootResponse struct {
	LogID           []byte `cbor:"logId"`
	Alg             string `cbor:"alg"`
	X               []byte `cbor:"x"`
	Y               []byte `cbor:"y"`
	ChainID         string `cbor:"chainId,omitempty"`
	ContractAddress string `cbor:"contractAddress,omitempty"`
	Domain          string `cbor:"domain,omitempty"`
}
