package custodian

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/delegatekeys"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// registrarKey is a local stand-in for the KMS registrar voucher key.
func registrarKey(t *testing.T) (*ecdsa.PrivateKey, cose.Signer, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := cose.NewSigner(cose.AlgorithmES256, priv)
	require.NoError(t, err)
	kid, err := KidFromECDSAPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return priv, signer, kid
}

// delegatePub derives a standing delegate public key the way the sealer and
// custodian both do (shared package), so the voucher binds the real identity.
func delegatePub(t *testing.T, epoch uint32) *ecdsa.PublicKey {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv, err := delegatekeys.DeriveKey(seed, epoch, 0)
	require.NoError(t, err)
	return &priv.PublicKey
}

func TestVoucherRoundTrip(t *testing.T) {
	reg, signer, kid := registrarKey(t)
	claims := DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: delegatePub(t, 3)}

	voucher, err := BuildDelegateKeyVoucherWithSigner(claims, kid, signer)
	require.NoError(t, err)

	require.NoError(t, VerifyDelegateKeyVoucher(voucher, &reg.PublicKey, claims),
		"a voucher must verify against the pinned registrar key with matching claims")
}

func TestVoucherRejectsWrongRegistrarKey(t *testing.T) {
	_, signer, kid := registrarKey(t)
	claims := DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: delegatePub(t, 3)}
	voucher, err := BuildDelegateKeyVoucherWithSigner(claims, kid, signer)
	require.NoError(t, err)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	require.Error(t, VerifyDelegateKeyVoucher(voucher, &other.PublicKey, claims),
		"a voucher signed by a different key must not verify against the pinned key")
}

func TestVoucherRejectsClaimTamper(t *testing.T) {
	reg, signer, kid := registrarKey(t)
	claims := DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: delegatePub(t, 3)}
	voucher, err := BuildDelegateKeyVoucherWithSigner(claims, kid, signer)
	require.NoError(t, err)

	// Same signature, but the caller expects a different epoch / sealer / key.
	require.Error(t, VerifyDelegateKeyVoucher(voucher, &reg.PublicKey,
		DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 4, PublicKey: delegatePub(t, 3)}),
		"epoch mismatch must fail")
	require.Error(t, VerifyDelegateKeyVoucher(voucher, &reg.PublicKey,
		DelegateKeyVoucherClaims{SealerID: "sealer-b", Epoch: 3, PublicKey: delegatePub(t, 3)}),
		"sealerId mismatch must fail")
	require.Error(t, VerifyDelegateKeyVoucher(voucher, &reg.PublicKey,
		DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: delegatePub(t, 4)}),
		"delegate-key mismatch must fail")
}

func TestVoucherRejectsEmptyClaims(t *testing.T) {
	_, signer, kid := registrarKey(t)
	_, err := BuildDelegateKeyVoucherWithSigner(
		DelegateKeyVoucherClaims{SealerID: "", Epoch: 3, PublicKey: delegatePub(t, 3)}, kid, signer)
	require.Error(t, err, "empty sealerId must be rejected at build")
	_, err = BuildDelegateKeyVoucherWithSigner(
		DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 0, PublicKey: delegatePub(t, 3)}, kid, signer)
	require.Error(t, err, "epoch 0 must be rejected at build")
}
