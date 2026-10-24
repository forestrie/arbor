package custodian

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegatekeys"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// The delegate-key voucher conformance vector: one voucher, the registrar key
// that signed it, its claims and expiry cases. The source of truth is
// forestrie/protocol vectors/fixtures/delegate-key-voucher.json; this is a
// byte-identical copy, pinned by SHA-256 below. canopy
// packages/shared/encoding/src/testdata/ holds the same bytes, so the Go and
// TypeScript verifiers are held to one voucher. Do not edit the copy; change
// protocol and re-copy.
const (
	voucherVectorPath   = "testdata/delegate-key-voucher.json"
	voucherVectorSHA256 = "48e7b6b12e3f0f82bc83ee1ce2a36b8947a7a1359390d51ef0f0849b6e57727d"
)

type voucherVector struct {
	Version     int    `json:"version"`
	Description string `json:"description"`
	Generator   string `json:"generator"`
	Conventions struct {
		Hex      string `json:"hex"`
		NotAfter string `json:"not_after"`
		Now      string `json:"now"`
	} `json:"conventions"`
	Registrar struct {
		Alg            string `json:"alg"`
		PublicKeyXYHex string `json:"public_key_xy_hex"`
		PrivateKeyDHex string `json:"private_key_d_hex"`
	} `json:"registrar"`
	Claims struct {
		SealerID         string `json:"sealer_id"`
		Epoch            uint32 `json:"epoch"`
		PublicKeyCoseHex string `json:"public_key_cose_hex"`
		NotAfter         int64  `json:"not_after"`
	} `json:"claims"`
	PayloadHex string              `json:"payload_hex"`
	VoucherHex string              `json:"voucher_hex"`
	Cases      []voucherVectorCase `json:"cases"`
}

type voucherVectorCase struct {
	Name            string `json:"name"`
	Now             int64  `json:"now"`
	RequireNotAfter bool   `json:"require_not_after"`
	Result          string `json:"result"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// coseKeyToECDSA parses a canonical EC2 P-256 COSE_Key.
func coseKeyToECDSA(t *testing.T, raw []byte) *ecdsa.PublicKey {
	t.Helper()
	var m map[int]any
	require.NoError(t, cbor.Unmarshal(raw, &m))
	x, okX := m[-2].([]byte)
	y, okY := m[-3].([]byte)
	require.True(t, okX && okY, "COSE_Key needs -2 and -3")
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
}

// TestDelegateKeyVoucherVector: the Go builder and verifier agree with the
// shared vector. Re-encoding the claims yields the signed payload exactly,
// the voucher verifies against the registrar key, and each expiry case gives
// the stated result.
func TestDelegateKeyVoucherVector(t *testing.T) {
	raw, err := os.ReadFile(voucherVectorPath)
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	require.Equal(t, voucherVectorSHA256, hex.EncodeToString(sum[:]), "vendored vector differs from the pinned protocol bytes")

	var v voucherVector
	require.NoError(t, json.Unmarshal(raw, &v))
	xy := mustHex(t, v.Registrar.PublicKeyXYHex)
	require.Len(t, xy, 64)
	registrar := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xy[:32]), Y: new(big.Int).SetBytes(xy[32:])}

	coseKey := mustHex(t, v.Claims.PublicKeyCoseHex)
	delegate := coseKeyToECDSA(t, coseKey)
	canonical, err := delegatekeys.CoseKeyBytes(delegate)
	require.NoError(t, err)
	require.Equal(t, coseKey, canonical, "the vector's COSE_Key is the canonical encoding")

	claims := DelegateKeyVoucherClaims{SealerID: v.Claims.SealerID, Epoch: v.Claims.Epoch, PublicKey: delegate, NotAfter: v.Claims.NotAfter}
	payload, err := encodeVoucherClaims(claims)
	require.NoError(t, err)
	require.Equal(t, v.PayloadHex, hex.EncodeToString(payload), "builder payload matches the vector")

	var u cose.UntaggedSign1Message
	require.NoError(t, u.UnmarshalCBOR(mustHex(t, v.VoucherHex)))
	require.Equal(t, v.PayloadHex, hex.EncodeToString(u.Payload), "voucher signs the vector payload")

	require.NotEmpty(t, v.Cases)
	for _, c := range v.Cases {
		notAfter, err := VerifyDelegateKeyVoucher(mustHex(t, v.VoucherHex), registrar, claims,
			time.Unix(c.Now, 0), VerifyDelegateKeyVoucherOptions{RequireNotAfter: c.RequireNotAfter})
		switch c.Result {
		case "ok":
			require.NoError(t, err, c.Name)
			require.Equal(t, v.Claims.NotAfter, notAfter, c.Name)
		case "expired":
			require.True(t, errors.Is(err, ErrVoucherExpired), "%s: %v", c.Name, err)
		case "not_after_missing":
			require.True(t, errors.Is(err, ErrVoucherNotAfterMissing), "%s: %v", c.Name, err)
		default:
			t.Fatalf("%s: unknown result %q", c.Name, c.Result)
		}
	}
}

// TestGenerateDelegateKeyVoucherVector writes a fresh vector to
// $VOUCHER_VECTOR_OUT with the production builder. ES256 signatures are
// randomised, so a rerun yields different, equally valid voucher bytes;
// the committed protocol vector is the reference, not this generator.
func TestGenerateDelegateKeyVoucherVector(t *testing.T) {
	out := os.Getenv("VOUCHER_VECTOR_OUT")
	if out == "" {
		t.Skip("set VOUCHER_VECTOR_OUT to regenerate the voucher vector")
	}
	// A fixed, published test scalar; never a deployed key.
	d := sha256.Sum256([]byte("forestrie test vector: delegate-key voucher registrar"))
	curve := elliptic.P256()
	priv := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(d[:])}
	priv.PublicKey.Curve = curve
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d[:])
	signer, err := cose.NewSigner(cose.AlgorithmES256, priv)
	require.NoError(t, err)
	kid, err := KidFromECDSAPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	const notAfter = int64(1_800_086_400)
	claims := DelegateKeyVoucherClaims{SealerID: "sealer-vector", Epoch: 2, PublicKey: delegatePub(t, 2), NotAfter: notAfter}
	voucher, err := BuildDelegateKeyVoucherWithSigner(claims, kid, signer)
	require.NoError(t, err)
	payload, err := encodeVoucherClaims(claims)
	require.NoError(t, err)
	coseKey, err := delegatekeys.CoseKeyBytes(claims.PublicKey)
	require.NoError(t, err)

	var v voucherVector
	v.Version = 1
	v.Description = "Delegate-key registrar voucher: an untagged COSE_Sign1 (ES256) over the canonical int-keyed claims map {1: sealerId, 2: epoch, 3: delegate COSE_Key, 4: notAfter}, with the registrar key that signed it and expiry cases (plan-2609-12 slice 07)."
	v.Generator = "forestrie/arbor services/custodian/src/voucher_vector_test.go TestGenerateDelegateKeyVoucherVector (BuildDelegateKeyVoucherWithSigner)"
	v.Conventions.Hex = "unprefixed lowercase"
	v.Conventions.NotAfter = "claim 4, Unix seconds"
	v.Conventions.Now = "Unix seconds; a voucher is expired when now >= not_after"
	v.Registrar.Alg = "ES256"
	v.Registrar.PublicKeyXYHex = hex.EncodeToString(append(priv.PublicKey.X.FillBytes(make([]byte, 32)), priv.PublicKey.Y.FillBytes(make([]byte, 32))...))
	v.Registrar.PrivateKeyDHex = hex.EncodeToString(d[:])
	v.Claims.SealerID = claims.SealerID
	v.Claims.Epoch = claims.Epoch
	v.Claims.PublicKeyCoseHex = hex.EncodeToString(coseKey)
	v.Claims.NotAfter = notAfter
	v.PayloadHex = hex.EncodeToString(payload)
	v.VoucherHex = hex.EncodeToString(voucher)
	v.Cases = []voucherVectorCase{
		{Name: "one second before not_after", Now: notAfter - 1, RequireNotAfter: true, Result: "ok"},
		{Name: "at not_after", Now: notAfter, RequireNotAfter: true, Result: "expired"},
		{Name: "after not_after, claim 4 not required", Now: notAfter + 1, RequireNotAfter: false, Result: "expired"},
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(v))
	require.NoError(t, os.WriteFile(out, b.Bytes(), 0o644))
}
