package univocity

// Forest genesis CBOR map labels (canopy forest-genesis-labels.ts).
const (
	labelGenesisVersion    = -68009
	labelBootstrapLogID    = -68010
	labelUnivocityAddr     = -68011
	labelUnivocityChainIDs = -68012 // legacy; rejected on v1
	labelChainID           = -68013
	genesisSchemaV1        = 1
)

// COSE_Key map labels carried by the forest genesis document (canopy
// cose/cose-key.ts). The genesis key is the forest bootstrap/authority key.
const (
	coseKeyKty   = 1
	coseKeyAlg   = 3
	coseEc2Crv   = -1
	coseEc2X     = -2
	coseEc2Y     = -3
	coseKtyEc2   = 2
	coseCrvP256  = 1
	coseAlgES256 = -7
)
