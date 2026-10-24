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
	legacy := signRawVoucher(t, signer, kid, payload)

	want := DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: pub}
	notAfter, err := VerifyDelegateKeyVoucher(legacy, &reg.PublicKey, want, testNow, VerifyDelegateKeyVoucherOptions{})
	require.NoError(t, err)
	require.Zero(t, notAfter, "absent claim 4 decodes as 0")
	_, err = VerifyDelegateKeyVoucher(legacy, &reg.PublicKey, want, testNow, VerifyDelegateKeyVoucherOptions{RequireNotAfter: true})
	require.True(t, errors.Is(err, ErrVoucherNotAfterMissing), "got %v", err)
}

// TestVoucherExplicitZeroNotAfter: an explicit claim 4 of 0 is present, so
// it is expired, never treated as absent (agreeing with the TS verifier).
func TestVoucherExplicitZeroNotAfter(t *testing.T) {
	reg, signer, kid := registrarKey(t)
	pub := delegatePub(t, 3)
	keyBytes, err := delegatekeys.CoseKeyBytes(pub)
	require.NoError(t, err)
	payload, err := canonicalVoucherCBOR.Marshal(map[int]any{1: "sealer-a", 2: uint32(3), 3: keyBytes, 4: uint64(0)})
	require.NoError(t, err)
	v := signRawVoucher(t, signer, kid, payload)

	want := DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: pub}
	for _, opts := range []VerifyDelegateKeyVoucherOptions{{}, {RequireNotAfter: true}} {
		_, err = VerifyDelegateKeyVoucher(v, &reg.PublicKey, want, testNow, opts)
		require.True(t, errors.Is(err, ErrVoucherExpired), "claim 4 = 0 must be expired: %v", err)
	}
}

// TestVoucherStrictClaimsDecoding: an unknown claim or a duplicated claim
// key fails closed (platform P16: strict deterministic decoding).
func TestVoucherStrictClaimsDecoding(t *testing.T) {
	reg, signer, kid := registrarKey(t)
	pub := delegatePub(t, 3)
	keyBytes, err := delegatekeys.CoseKeyBytes(pub)
	require.NoError(t, err)
	want := DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 3, PublicKey: pub}

	unknown, err := canonicalVoucherCBOR.Marshal(map[int]any{1: "sealer-a", 2: uint32(3), 3: keyBytes, 4: uint64(testNotAfter), 5: "extra"})
	require.NoError(t, err)
	_, err = VerifyDelegateKeyVoucher(signRawVoucher(t, signer, kid, unknown), &reg.PublicKey, want, testNow, VerifyDelegateKeyVoucherOptions{})
	require.Error(t, err, "unknown claim 5 must be refused")

	// {1: "sealer-a", 1: "sealer-a", 2: 3, 3: key}: claim 1 twice.
	sealer, err := canonicalVoucherCBOR.Marshal("sealer-a")
	require.NoError(t, err)
	key, err := canonicalVoucherCBOR.Marshal(keyBytes)
	require.NoError(t, err)
	dup := append([]byte{0xa4, 0x01}, sealer...)
	dup = append(append(dup, 0x01), sealer...)
	dup = append(dup, 0x02, 0x03, 0x03)
	dup = append(dup, key...)
	_, err = VerifyDelegateKeyVoucher(signRawVoucher(t, signer, kid, dup), &reg.PublicKey, want, testNow, VerifyDelegateKeyVoucherOptions{})
	require.Error(t, err, "a duplicated claim key must be refused")
}

// signRawVoucher signs an arbitrary claims payload with the voucher's
// protected header, so tests and the vector generator can build vouchers the
// production builder refuses to issue.
func signRawVoucher(t *testing.T, signer cose.Signer, kid, payload []byte) []byte {
	t.Helper()
	msg := cose.NewSign1Message()
	msg.Headers.Protected = cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm:   signer.Algorithm(),
		cose.HeaderLabelContentType: delegateKeyVoucherCTY,
		cose.HeaderLabelKeyID:       kid,
	}
	msg.Payload = payload
	require.NoError(t, msg.Sign(rand.Reader, nil, signer))
	u := cose.UntaggedSign1Message(*msg)
	out, err := u.MarshalCBOR()
	require.NoError(t, err)
	return out
}
