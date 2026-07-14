package custodian

import (
	"encoding/base64"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/delegatekeys"
	"github.com/stretchr/testify/require"
)

// TestBuildDelegateKeyRegistration proves the registration body binds the
// derived standing key and a voucher that verifies against the registrar key —
// the two things the coordinator (H1) checks.
func TestBuildDelegateKeyRegistration(t *testing.T) {
	reg, signer, kid := registrarKey(t) // helper from voucher_test.go
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	body, err := buildDelegateKeyRegistration("sealer-a", 3, 999, seed,
		func(c DelegateKeyVoucherClaims) ([]byte, error) {
			return BuildDelegateKeyVoucherWithSigner(c, kid, signer)
		})
	require.NoError(t, err)

	require.Equal(t, "sealer-a", body.SealerID)
	require.Len(t, body.Keys, 1)
	entry := body.Keys[0]
	require.Equal(t, "ES256", entry.Alg)
	require.Equal(t, uint32(3), entry.Epoch)
	require.Equal(t, int64(999), entry.NotAfter)

	// publicKey is the derived key's canonical COSE bytes (matches the sealer's
	// key and the coordinator's delegated_pubkey_hash preimage).
	priv, err := delegatekeys.DeriveKey(seed, 3, 0)
	require.NoError(t, err)
	wantCose, err := delegatekeys.CoseKeyBytes(&priv.PublicKey)
	require.NoError(t, err)
	gotCose, err := base64.StdEncoding.DecodeString(entry.PublicKey)
	require.NoError(t, err)
	require.Equal(t, wantCose, gotCose)

	// The voucher verifies against the registrar key for the derived key.
	voucher, err := base64.StdEncoding.DecodeString(entry.Voucher)
	require.NoError(t, err)
	require.NoError(t, VerifyDelegateKeyVoucher(voucher, &reg.PublicKey,
		DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: &priv.PublicKey}))
}
