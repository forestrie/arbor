package univocity

// TrustRootResponse is the plan-0003 CBOR shape consumed by sealer.
type TrustRootResponse struct {
	LogID           []byte `cbor:"logId"`
	Alg             string `cbor:"alg"`
	X               []byte `cbor:"x"`
	Y               []byte `cbor:"y"`
	ChainID         string `cbor:"chainId,omitempty"`
	ContractAddress string `cbor:"contractAddress,omitempty"`
}
