package univocity

// Forest genesis CBOR map labels (canopy forest-genesis-labels.ts).
const (
	labelGenesisVersion    = -68009
	labelBootstrapLogID    = -68010
	labelUnivocityAddr     = -68011
	labelUnivocityChainIDs = -68012 // legacy; rejected on v1
	labelChainID           = -68013
	labelBootstrapAlg      = -68014 // bootstrap-alg: int COSE alg (-7 | -65799)
	labelBootstrapKey      = -68015 // bootstrap-key: bstr opaque 64 (ES256) or 20 (KS256)
	genesisSchemaV1        = 1
	genesisSchemaV2        = 2
)

func validGenesisSchemaVersion(v uint64) bool {
	return v == genesisSchemaV1 || v == genesisSchemaV2
}

// COSE_Key map labels carried by the v1 forest genesis document (canopy
// cose/cose-key.ts). Legacy ES256 genesis uses an embedded EC2/P-256 key.
const (
	coseKeyKty   = 1
	coseKeyAlg   = 3
	coseEc2Crv   = -1
	coseEc2X     = -2
	coseEc2Y     = -3
	coseKtyEc2   = 2
	coseCrvP256  = 1
	coseAlgES256 = -7
	coseAlgKS256 = -65799
)
