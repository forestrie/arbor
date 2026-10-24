package custodian

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

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
	claims := DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: delegatePub(t, 3), NotAfter: testNotAfter}

	voucher, err := BuildDelegateKeyVoucherWithSigner(claims, kid, signer)
	require.NoError(t, err)

	notAfter, err := VerifyDelegateKeyVoucher(voucher, &reg.PublicKey, claims, testNow, VerifyDelegateKeyVoucherOptions{RequireNotAfter: true})
	require.NoError(t, err, "a voucher must verify against the pinned registrar key with matching claims")
	require.Equal(t, testNotAfter, notAfter, "claim 4 round-trips")
}

func TestVoucherRejectsWrongRegistrarKey(t *testing.T) {
	_, signer, kid := registrarKey(t)
	claims := DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: delegatePub(t, 3), NotAfter: testNotAfter}
	voucher, err := BuildDelegateKeyVoucherWithSigner(claims, kid, signer)
	require.NoError(t, err)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = VerifyDelegateKeyVoucher(voucher, &other.PublicKey, claims, testNow, VerifyDelegateKeyVoucherOptions{})
	require.Error(t, err,
		"a voucher signed by a different key must not verify against the pinned key")
}

func TestVoucherRejectsClaimTamper(t *testing.T) {
	reg, signer, kid := registrarKey(t)
	claims := DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: delegatePub(t, 3), NotAfter: testNotAfter}
	voucher, err := BuildDelegateKeyVoucherWithSigner(claims, kid, signer)
	require.NoError(t, err)

	// Same signature, but the caller expects a different epoch / sealer / key
	// / notAfter.
	for name, want := range map[string]DelegateKeyVoucherClaims{
		"epoch":    {SealerID: "sealer-a", Epoch: 4, PublicKey: delegatePub(t, 3)},
		"sealerId": {SealerID: "sealer-b", Epoch: 3, PublicKey: delegatePub(t, 3)},
		"key":      {SealerID: "sealer-a", Epoch: 3, PublicKey: delegatePub(t, 4)},
		"notAfter": {SealerID: "sealer-a", Epoch: 3, PublicKey: delegatePub(t, 3), NotAfter: testNotAfter + 1},
	} {
		_, err := VerifyDelegateKeyVoucher(voucher, &reg.PublicKey, want, testNow, VerifyDelegateKeyVoucherOptions{})
		require.Error(t, err, "%s mismatch must fail", name)
	}
}

func TestVoucherRejectsEmptyClaims(t *testing.T) {
	_, signer, kid := registrarKey(t)
	_, err := BuildDelegateKeyVoucherWithSigner(
		DelegateKeyVoucherClaims{SealerID: "", Epoch: 3, PublicKey: delegatePub(t, 3)}, kid, signer)
	require.Error(t, err, "empty sealerId must be rejected at build")
	_, err = BuildDelegateKeyVoucherWithSigner(
		DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 0, PublicKey: delegatePub(t, 3)}, kid, signer)
	require.Error(t, err, "epoch 0 must be rejected at build")
	_, err = BuildDelegateKeyVoucherWithSigner(
		DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: delegatePub(t, 3)}, kid, signer)
	require.Error(t, err, "a voucher without claim 4 (notAfter) must be rejected at build")
}

// testNow and testNotAfter are a fixed signing instant and claim 4 one day
// later, so expiry tests do not depend on the wall clock.
var (
	testNow      = time.Unix(1_800_000_000, 0)
	testNotAfter = testNow.Add(24 * time.Hour).Unix()
)

// TestVoucherNotAfterExpiry: claim 4 is checked against now whenever it is
// present; a voucher is expired once now reaches notAfter.
func TestVoucherNotAfterExpiry(t *testing.T) {
	reg, signer, kid := registrarKey(t)
	claims := DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: delegatePub(t, 3), NotAfter: testNotAfter}
	voucher, err := BuildDelegateKeyVoucherWithSigner(claims, kid, signer)
	require.NoError(t, err)

	for _, opts := range []VerifyDelegateKeyVoucherOptions{{}, {RequireNotAfter: true}} {
		_, err = VerifyDelegateKeyVoucher(voucher, &reg.PublicKey, claims, time.Unix(testNotAfter-1, 0), opts)
		require.NoError(t, err, "one second before notAfter is valid")
		_, err = VerifyDelegateKeyVoucher(voucher, &reg.PublicKey, claims, time.Unix(testNotAfter, 0), opts)
		require.True(t, errors.Is(err, ErrVoucherExpired), "at notAfter: %v", err)
	}
}

// TestVoucherWithoutNotAfter: a claim-4-less voucher (issued before slice 07)
// verifies without RequireNotAfter and fails not_after_missing with it.
func TestVoucherWithoutNotAfter(t *testing.T) {
	reg, signer, kid := registrarKey(t)
	pub := delegatePub(t, 3)
	keyBytes, err := delegatekeys.CoseKeyBytes(pub)
	require.NoError(t, err)
	payload, err := canonicalVoucherCBOR.Marshal(map[int]any{1: "sealer-a", 2: uint32(3), 3: keyBytes})
	require.NoError(t, err)
	msg := cose.NewSign1Message()
	msg.Headers.Protected = cose.ProtectedHeader{cose.HeaderLabelAlgorithm: signer.Algorithm(), cose.HeaderLabelKeyID: kid}
	msg.Payload = payload
	require.NoError(t, msg.Sign(rand.Reader, nil, signer))
	u := cose.UntaggedSign1Message(*msg)
	legacy, err := u.MarshalCBOR()
	require.NoError(t, err)

	want := DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: pub}
	notAfter, err := VerifyDelegateKeyVoucher(legacy, &reg.PublicKey, want, testNow, VerifyDelegateKeyVoucherOptions{})
	require.NoError(t, err)
	require.Zero(t, notAfter, "absent claim 4 decodes as 0")
	_, err = VerifyDelegateKeyVoucher(legacy, &reg.PublicKey, want, testNow, VerifyDelegateKeyVoucherOptions{RequireNotAfter: true})
	require.True(t, errors.Is(err, ErrVoucherNotAfterMissing), "got %v", err)
}
