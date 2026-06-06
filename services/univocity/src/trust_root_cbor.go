package univocity

// TrustRootResponse is the CBOR trust-root shape consumed by sealer and canopy.
// Root identity is (alg:int, key:bstr): 64 bytes ES256 x||y or 20-byte KS256 address.
type TrustRootResponse struct {
	LogID           []byte `cbor:"logId"`
	Alg             int64  `cbor:"alg"`
	Key             []byte `cbor:"key"`
	ChainID         string `cbor:"chainId,omitempty"`
	ContractAddress string `cbor:"contractAddress,omitempty"`
}
