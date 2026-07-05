package delegationcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func newTestDelegatedKey(t *testing.T) (*DelegatedCoseKey, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	x := make([]byte, 32)
	y := make([]byte, 32)
	key.PublicKey.X.FillBytes(x)
	key.PublicKey.Y.FillBytes(y)
	dk, err := NewDelegatedCoseKey(Secp256r1, x, y)
	require.NoError(t, err)
	return dk, key
}

// The Sig_structure must byte-match the contract's
// buildSigStructure(protected, abi.encodePacked(domain, logId, mmrStart,
// mmrEnd, keyX, keyY)) - array of 4 with the packed payload as a bstr.
func TestBuildOnchainDelegationToBeSignedBytes(t *testing.T) {
	dk, _ := newTestDelegatedKey(t)
	logIdHex := "101112131415161718191a1b1c1d1e1f"

	tbs, err := BuildOnchainDelegationToBeSigned(logIdHex, 3, 1<<40, dk)
	require.NoError(t, err)
	require.Equal(t, []byte{0xa1, 0x01, 0x26}, tbs.ProtectedHeader, "protected header must be {1: ES256}")
	require.Equal(t, append(append([]byte{}, dk.X...), dk.Y...), tbs.DelegationKey)

	// Decode the Sig_structure and reconstruct the packed payload.
	var arr []cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(tbs.SigStructure, &arr))
	require.Len(t, arr, 4)
	var context string
	require.NoError(t, cbor.Unmarshal(arr[0], &context))
	require.Equal(t, "Signature1", context)
	var protected, external, payload []byte
	require.NoError(t, cbor.Unmarshal(arr[1], &protected))
	require.Equal(t, tbs.ProtectedHeader, protected)
	require.NoError(t, cbor.Unmarshal(arr[2], &external))
	require.Empty(t, external)
	require.NoError(t, cbor.Unmarshal(arr[3], &payload))

	expected := []byte(OnchainDelegationDomain)
	logID32, err := LogID32FromHex(logIdHex)
	require.NoError(t, err)
	expected = append(expected, logID32[:]...)
	expected = binary.BigEndian.AppendUint64(expected, 3)
	expected = binary.BigEndian.AppendUint64(expected, 1<<40)
	expected = append(expected, dk.X...)
	expected = append(expected, dk.Y...)
	require.Equal(t, expected, payload)

	// The bytes32 log id is the 16 id bytes right-aligned.
	require.Equal(t, make([]byte, 16), logID32[:16])
	require.Equal(t, "101112131415161718191a1b1c1d1e1f", cborHex(logID32[16:]))
}

func cborHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0xf])
	}
	return string(out)
}

// An ES256 root signature over the digest assembles into a proof that
// verifies for the same digest, always in low-s form.
func TestAssembleOnchainDelegationProofLowS(t *testing.T) {
	dk, _ := newTestDelegatedKey(t)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tbs, err := BuildOnchainDelegationToBeSigned("101112131415161718191a1b1c1d1e1f", 0, 1<<40, dk)
	require.NoError(t, err)
	digest := sha256.Sum256(tbs.SigStructure)

	halfN := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	// 32 signatures: all-low-s by chance is ~2^-32.
	for range 32 {
		r, s, err := ecdsa.Sign(rand.Reader, rootKey, digest[:])
		require.NoError(t, err)
		raw := make([]byte, 64)
		r.FillBytes(raw[:32])
		s.FillBytes(raw[32:])

		proof, err := AssembleOnchainDelegationProof(tbs, 0, 1<<40, raw)
		require.NoError(t, err)
		require.Equal(t, tbs.DelegationKey, proof.DelegationKey)

		ps := new(big.Int).SetBytes(proof.Signature[32:])
		require.LessOrEqual(t, ps.Cmp(halfN), 0, "assembled signature must be low-s")
		pr := new(big.Int).SetBytes(proof.Signature[:32])
		require.True(t, ecdsa.Verify(&rootKey.PublicKey, digest[:], pr, ps),
			"normalized signature must verify for the same digest")
	}
}
