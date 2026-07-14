package delegatekeys

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// goldenSeed is a fixed 32-byte seed used to pin the derivation wire. It is not
// a real seed — real seeds come from the custodian KMS-MAC endpoint.
func goldenSeed() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

// TestGoldenVector pins the (seed, epoch, index) -> delegated_pubkey_hash wire.
// If this changes, the sealer and custodian would derive different public keys
// and every coverage-retrieval lookup would silently miss. Any intentional
// change to the derivation MUST update this constant deliberately.
func TestGoldenVector(t *testing.T) {
	// Pinned: PubkeyHashHex(DeriveKey(goldenSeed, epoch=1, index=0)).
	const wantHash = "2d50e8a5b9dde305b195a772879715c49e0441e2d3ede4745709681548c7d57f"

	priv, err := DeriveKey(goldenSeed(), 1, 0)
	require.NoError(t, err)
	got, err := PubkeyHashHex(&priv.PublicKey)
	require.NoError(t, err)
	require.Equal(t, wantHash, got, "delegation-key derivation wire changed — sealer/custodian would drift")
}

// TestDeterministic asserts the derivation is a pure function of its inputs:
// the restart-survival property (ADR-0050 Q3) depends on it.
func TestDeterministic(t *testing.T) {
	a, err := DeriveKey(goldenSeed(), 3, 0)
	require.NoError(t, err)
	b, err := DeriveKey(goldenSeed(), 3, 0)
	require.NoError(t, err)
	require.Equal(t, a.D.Bytes(), b.D.Bytes())
}

// TestDistinct asserts epoch and index each vary the key, so N/N-1 overlap and
// multiple indices never collide.
func TestDistinct(t *testing.T) {
	base, err := DeriveKey(goldenSeed(), 2, 0)
	require.NoError(t, err)
	byEpoch, err := DeriveKey(goldenSeed(), 3, 0)
	require.NoError(t, err)
	byIndex, err := DeriveKey(goldenSeed(), 2, 1)
	require.NoError(t, err)
	require.NotEqual(t, base.D.Bytes(), byEpoch.D.Bytes(), "epoch must vary the key")
	require.NotEqual(t, base.D.Bytes(), byIndex.D.Bytes(), "index must vary the key")
}

// TestCoseKeyHashConsistency asserts PubkeyHashHex == hex(sha256(CoseKeyBytes)),
// the exact identity the coordinator stores as delegated_pubkey_hash.
func TestCoseKeyHashConsistency(t *testing.T) {
	priv, err := DeriveKey(goldenSeed(), 1, 0)
	require.NoError(t, err)
	cose, err := CoseKeyBytes(&priv.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(cose)
	h, err := PubkeyHashHex(&priv.PublicKey)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(sum[:]), h)
}
