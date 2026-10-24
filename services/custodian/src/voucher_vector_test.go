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
	voucherVectorSHA256 = "9dce83715cbdacb23c5f71e4e1fc63fb6e7c57b34ab84c80e80f601f1eb7b8c1"
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
	Vouchers []voucherVectorEntry `json:"vouchers"`
}

// voucherVectorEntry is one voucher. Claims.NotAfter is nil when the voucher
// has no claim 4, and points at 0 for an explicit 4: 0.
type voucherVectorEntry struct {
	Name   string `json:"name"`
	Claims struct {
		SealerID         string `json:"sealer_id"`
		Epoch            uint32 `json:"epoch"`
		PublicKeyCoseHex string `json:"public_key_cose_hex"`
		NotAfter         *int64 `json:"not_after,omitempty"`
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

// vectorClaimsPayload encodes an entry's claims the way the vector states
// them: claim 4 only when present.
func vectorClaimsPayload(t *testing.T, e voucherVectorEntry) []byte {
	t.Helper()
	m := map[int]any{1: e.Claims.SealerID, 2: e.Claims.Epoch, 3: mustHex(t, e.Claims.PublicKeyCoseHex)}
	if e.Claims.NotAfter != nil {
		m[4] = uint64(*e.Claims.NotAfter)
	}
	b, err := canonicalVoucherCBOR.Marshal(m)
	require.NoError(t, err)
	return b
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

	require.Len(t, v.Vouchers, 3, "claim 4 set, absent, and explicit 0")
	for _, e := range v.Vouchers {
		coseKey := mustHex(t, e.Claims.PublicKeyCoseHex)
		delegate := coseKeyToECDSA(t, coseKey)
		canonical, err := delegatekeys.CoseKeyBytes(delegate)
		require.NoError(t, err)
		require.Equal(t, coseKey, canonical, "%s: the COSE_Key is the canonical encoding", e.Name)

		payload := vectorClaimsPayload(t, e)
		require.Equal(t, e.PayloadHex, hex.EncodeToString(payload), "%s: claims re-encode to the payload", e.Name)
		want := DelegateKeyVoucherClaims{SealerID: e.Claims.SealerID, Epoch: e.Claims.Epoch, PublicKey: delegate}
		if e.Claims.NotAfter != nil && *e.Claims.NotAfter > 0 {
			// The production builder issues only this shape.
			want.NotAfter = *e.Claims.NotAfter
			built, err := encodeVoucherClaims(want)
			require.NoError(t, err)
			require.Equal(t, e.PayloadHex, hex.EncodeToString(built), "%s: builder payload matches", e.Name)
		}

		var u cose.UntaggedSign1Message
		require.NoError(t, u.UnmarshalCBOR(mustHex(t, e.VoucherHex)))
		require.Equal(t, e.PayloadHex, hex.EncodeToString(u.Payload), "%s: voucher signs the payload", e.Name)

		require.NotEmpty(t, e.Cases)
		for _, c := range e.Cases {
			name := e.Name + ": " + c.Name
			notAfter, err := VerifyDelegateKeyVoucher(mustHex(t, e.VoucherHex), registrar, want,
				time.Unix(c.Now, 0), VerifyDelegateKeyVoucherOptions{RequireNotAfter: c.RequireNotAfter})
			switch c.Result {
			case "ok":
				require.NoError(t, err, name)
				if e.Claims.NotAfter != nil {
					require.Equal(t, *e.Claims.NotAfter, notAfter, name)
				}
			case "expired":
				require.True(t, errors.Is(err, ErrVoucherExpired), "%s: %v", name, err)
			case "not_after_missing":
				require.True(t, errors.Is(err, ErrVoucherNotAfterMissing), "%s: %v", name, err)
			default:
				t.Fatalf("%s: unknown result %q", name, c.Result)
			}
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
	pub := delegatePub(t, 2)
	coseKey, err := delegatekeys.CoseKeyBytes(pub)
	require.NoError(t, err)
	entry := func(name string, claim4 *int64, cases []voucherVectorCase) voucherVectorEntry {
		var e voucherVectorEntry
		e.Name = name
		e.Claims.SealerID = "sealer-vector"
		e.Claims.Epoch = 2
		e.Claims.PublicKeyCoseHex = hex.EncodeToString(coseKey)
		e.Claims.NotAfter = claim4
		payload := vectorClaimsPayload(t, e)
		var voucher []byte
		if claim4 != nil && *claim4 > 0 {
			// The production path, for the voucher the custodian issues.
			voucher, err = BuildDelegateKeyVoucherWithSigner(
				DelegateKeyVoucherClaims{SealerID: "sealer-vector", Epoch: 2, PublicKey: pub, NotAfter: *claim4}, kid, signer)
			require.NoError(t, err)
		} else {
			voucher = signRawVoucher(t, signer, kid, payload)
		}
		e.PayloadHex = hex.EncodeToString(payload)
		e.VoucherHex = hex.EncodeToString(voucher)
		e.Cases = cases
		return e
	}
	na, zero := notAfter, int64(0)

	var v voucherVector
	v.Version = 1
	v.Description = "Delegate-key registrar vouchers: untagged COSE_Sign1 (ES256) over the canonical int-keyed claims map {1: sealerId, 2: epoch, 3: delegate COSE_Key, 4: notAfter}, with the registrar key that signed them and expiry cases: claim 4 set, claim 4 absent (issued before it existed), and an explicit claim 4 of 0 (present, so expired) (plan-2609-12 slice 07)."
	v.Generator = "forestrie/arbor services/custodian/src/voucher_vector_test.go TestGenerateDelegateKeyVoucherVector"
	v.Conventions.Hex = "unprefixed lowercase"
	v.Conventions.NotAfter = "claim 4, Unix seconds; omitted from claims when the voucher has no claim 4"
	v.Conventions.Now = "Unix seconds; a voucher with claim 4 is expired when now >= not_after"
	v.Registrar.Alg = "ES256"
	v.Registrar.PublicKeyXYHex = hex.EncodeToString(append(priv.PublicKey.X.FillBytes(make([]byte, 32)), priv.PublicKey.Y.FillBytes(make([]byte, 32))...))
	v.Registrar.PrivateKeyDHex = hex.EncodeToString(d[:])
	v.Vouchers = []voucherVectorEntry{
		entry("claim 4 set", &na, []voucherVectorCase{
			{Name: "one second before not_after", Now: notAfter - 1, RequireNotAfter: true, Result: "ok"},
			{Name: "at not_after", Now: notAfter, RequireNotAfter: true, Result: "expired"},
			{Name: "after not_after, claim 4 not required", Now: notAfter + 1, RequireNotAfter: false, Result: "expired"},
		}),
		entry("claim 4 absent", nil, []voucherVectorCase{
			{Name: "claim 4 not required", Now: notAfter, RequireNotAfter: false, Result: "ok"},
			{Name: "claim 4 required", Now: notAfter, RequireNotAfter: true, Result: "not_after_missing"},
		}),
		entry("claim 4 explicitly 0", &zero, []voucherVectorCase{
			{Name: "claim 4 not required", Now: notAfter, RequireNotAfter: false, Result: "expired"},
			{Name: "claim 4 required", Now: notAfter, RequireNotAfter: true, Result: "expired"},
		}),
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(v))
	require.NoError(t, os.WriteFile(out, b.Bytes(), 0o644))
}
