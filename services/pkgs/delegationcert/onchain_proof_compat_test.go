package delegationcert

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// legacyOnchainDelegationProof is the historical 5-field wire shape, as
// encoded by every issuer and decoded by every consumer before algData
// existed. The compat tests below pin both directions of the upgrade.
type legacyOnchainDelegationProof struct {
	ProtectedHeader []byte `cbor:"protectedHeader"`
	DelegationKey   []byte `cbor:"delegationKey"`
	MMRStart        uint64 `cbor:"mmrStart"`
	MMREnd          uint64 `cbor:"mmrEnd"`
	Signature       []byte `cbor:"signature"`
}

func sampleProofFields() (protected, key, sig []byte) {
	return []byte{0xa1, 0x01, 0x26}, make([]byte, 64), make([]byte, 64)
}

// A legacy 5-field encoding decodes into the current struct (nil AlgData),
// and re-marshalling it stays byte-identical to the legacy bytes: omitempty
// keeps the plain ES256/KS256 wire unchanged both through the custodian's
// coordinator proxy and into the sealed checkpoint.
func TestOnchainDelegationProofDecodesLegacyFiveField(t *testing.T) {
	protected, key, sig := sampleProofFields()
	legacy := legacyOnchainDelegationProof{
		ProtectedHeader: protected,
		DelegationKey:   key,
		MMRStart:        7,
		MMREnd:          1 << 40,
		Signature:       sig,
	}
	legacyBytes, err := cbor.Marshal(legacy)
	require.NoError(t, err)

	var got OnchainDelegationProof
	require.NoError(t, cbor.Unmarshal(legacyBytes, &got))
	require.Equal(t, legacy.ProtectedHeader, got.ProtectedHeader)
	require.Equal(t, legacy.Signature, got.Signature)
	require.Nil(t, got.AlgData)

	remarshalled, err := cbor.Marshal(got)
	require.NoError(t, err)
	require.Equal(t, legacyBytes, remarshalled)
}

// A 6-field encoding with algData survives decode + re-marshal through the
// current struct — the custodian coordinator-proxy re-marshal path must not
// silently drop the assertion material — and a legacy consumer still decodes
// the fields it knows (fxamacker default ignores unknown keys).
func TestOnchainDelegationProofAlgDataRoundTripAndLegacyDecode(t *testing.T) {
	protected, key, sig := sampleProofFields()
	proof := OnchainDelegationProof{
		ProtectedHeader: protected,
		DelegationKey:   key,
		MMRStart:        7,
		MMREnd:          1 << 40,
		Signature:       sig,
		AlgData: [][]byte{
			make([]byte, 37),                  // authenticatorData
			[]byte(`{"type":"webauthn.get"}`), // clientDataJSON
			make([]byte, 16),                  // packed challengeIndex||typeIndex
		},
	}
	wire, err := cbor.Marshal(proof)
	require.NoError(t, err)

	var got OnchainDelegationProof
	require.NoError(t, cbor.Unmarshal(wire, &got))
	require.Equal(t, proof, got)

	rewire, err := cbor.Marshal(got)
	require.NoError(t, err)
	require.Equal(t, wire, rewire)

	var legacy legacyOnchainDelegationProof
	require.NoError(t, cbor.Unmarshal(wire, &legacy))
	require.Equal(t, proof.ProtectedHeader, legacy.ProtectedHeader)
	require.Equal(t, proof.Signature, legacy.Signature)
	require.Equal(t, proof.MMREnd, legacy.MMREnd)
}
