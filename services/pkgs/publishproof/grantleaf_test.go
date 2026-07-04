package publishproof

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Vector from go-univocity tests/fixtures/leaf_vectors.json (cross-language
// with univocity LibLogState._leafCommitment). 16-byte log ids occupy the low
// 16 bytes of the 32-byte contract fields.
func TestPublishGrantLeafCommitmentMatchesLibLogState(t *testing.T) {
	var idTimestamp [8]byte
	idTimestamp[7] = 0x01

	g := PublishGrant{
		LogId:      bytes32FromLow(t, "000102030405060708090a0b0c0d0e0f"),
		Grant:      big.NewInt(1),
		Request:    big.NewInt(0),
		MaxHeight:  1000,
		MinGrowth:  1,
		OwnerLogId: bytes32FromLow(t, "101112131415161718191a1b1c1d1e1f"),
		GrantData:  mustHex(t, "abcd"),
	}

	leaf, err := g.LeafCommitment(idTimestamp)
	require.NoError(t, err)
	require.Equal(t,
		"0bc4a0d26f57d59ca4dc604865be4c49a6221f1cbe65840e95e9905d02b30ea0",
		hex.EncodeToString(leaf[:]))
}

// Request is excluded from the commitment: changing it must not change the leaf.
func TestPublishGrantLeafCommitmentIgnoresRequest(t *testing.T) {
	var idTimestamp [8]byte
	idTimestamp[7] = 0x01

	g := PublishGrant{
		LogId:      bytes32FromLow(t, "000102030405060708090a0b0c0d0e0f"),
		Grant:      big.NewInt(1),
		Request:    new(big.Int).Lsh(big.NewInt(1), 224),
		MaxHeight:  1000,
		MinGrowth:  1,
		OwnerLogId: bytes32FromLow(t, "101112131415161718191a1b1c1d1e1f"),
		GrantData:  mustHex(t, "abcd"),
	}

	leaf, err := g.LeafCommitment(idTimestamp)
	require.NoError(t, err)
	require.Equal(t,
		"0bc4a0d26f57d59ca4dc604865be4c49a6221f1cbe65840e95e9905d02b30ea0",
		hex.EncodeToString(leaf[:]))
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func bytes32FromLow(t *testing.T, lowHex string) [32]byte {
	t.Helper()
	var out [32]byte
	b := mustHex(t, lowHex)
	copy(out[32-len(b):], b)
	return out
}
