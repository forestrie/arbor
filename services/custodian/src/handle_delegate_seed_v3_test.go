package custodian

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegatekeys"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// voucherSeedAPI is delegateSeedAPI with a registrar voucher key (an
// in-memory signer), a fixed clock and the given voucher TTL. It returns the
// API, the log sink and the registrar public key.
func voucherSeedAPI(t *testing.T, ttl time.Duration) (*API, *syncBuffer, *ecdsa.PublicKey) {
	t.Helper()
	logs := &syncBuffer{}
	api := NewAPI(slog.New(slog.NewJSONHandler(logs, nil)), Config{
		AppToken:              "app-token",
		DelegateSeedMacKey:    "projects/p/locations/l/keyRings/r/cryptoKeys/delegate-seed",
		DelegateSeedSealers:   []string{"sealer-a"},
		RegistrarVoucherKey:   "projects/p/locations/l/keyRings/r/cryptoKeys/registrar-voucher",
		DelegateKeyVoucherTTL: ttl,
	})
	api.macSignOverride = fakeMacSign(nil)
	api.getDelegateSeedKeyOverride = fakeDelegateSeedKey(goodMacKey, nil)
	require.NoError(t, api.probeDelegateSeedKey(context.Background()))
	api.now = func() time.Time { return testNow }
	reg, signer, kid := registrarKey(t)
	api.signVoucherOverride = func(_ context.Context, c DelegateKeyVoucherClaims) ([]byte, error) {
		return BuildDelegateKeyVoucherWithSigner(c, kid, signer)
	}
	return api, logs, &reg.PublicKey
}

// TestDelegateSeed_V3ReturnsVoucher: a version-3 request answers
// {seed, kmsKeyVersion, apiVersion: 3, voucher, voucherNotAfter}; the
// voucher binds the key derived from the returned seed, and its claim 4 and
// voucherNotAfter are both now + DELEGATE_KEY_VOUCHER_TTL.
func TestDelegateSeed_V3ReturnsVoucher(t *testing.T) {
	api, _, regPub := voucherSeedAPI(t, 6*time.Hour)
	rec := postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 2, APIVersion: 3})
	resp := decodeSeed(t, rec)
	require.Equal(t, uint32(3), resp.APIVersion)

	var raw map[string]any
	require.NoError(t, cbor.Unmarshal(rec.Body.Bytes(), &raw))
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	require.ElementsMatch(t, []string{"seed", "kmsKeyVersion", "apiVersion", "voucher", "voucherNotAfter"}, keys)

	wantNotAfter := testNow.Add(6 * time.Hour).Unix()
	require.Equal(t, wantNotAfter, resp.VoucherNotAfter)
	priv, err := delegatekeys.DeriveKey(resp.Seed, 2, 0)
	require.NoError(t, err)
	got, err := VerifyDelegateKeyVoucher(resp.Voucher, regPub,
		DelegateKeyVoucherClaims{SealerID: "sealer-a", Epoch: 2, PublicKey: &priv.PublicKey},
		testNow, VerifyDelegateKeyVoucherOptions{RequireNotAfter: true})
	require.NoError(t, err)
	require.Equal(t, wantNotAfter, got, "claim 4 is now + TTL")
}

// TestDelegateSeed_V3SignFailureStillReturnsSeed: when the voucher cannot be
// signed the seed is still answered at version 3, without a voucher, and the
// failure is logged at warn; the sealer installs the key and asks again.
func TestDelegateSeed_V3SignFailureStillReturnsSeed(t *testing.T) {
	api, logs, _ := voucherSeedAPI(t, 0)
	api.signVoucherOverride = func(context.Context, DelegateKeyVoucherClaims) ([]byte, error) {
		return nil, errors.New("kms AsymmetricSign: unavailable")
	}
	rec := postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 1, APIVersion: 3})
	resp := decodeSeed(t, rec)
	require.Equal(t, uint32(3), resp.APIVersion)
	require.Len(t, resp.Seed, 32)
	require.Nil(t, resp.Voucher)
	require.Zero(t, resp.VoucherNotAfter)

	var raw map[string]any
	require.NoError(t, cbor.Unmarshal(rec.Body.Bytes(), &raw))
	require.NotContains(t, raw, "voucher")
	require.NotContains(t, raw, "voucherNotAfter")
	require.Contains(t, logs.String(), `"level":"WARN","msg":"delegate key voucher not issued; answering the seed without it"`)
}

// TestDelegateSeed_V3WithoutRegistrarKey: a custodian with no
// REGISTRAR_VOUCHER_KEY serves version 3 without a voucher rather than
// refusing the seed.
func TestDelegateSeed_V3WithoutRegistrarKey(t *testing.T) {
	api := delegateSeedAPI(t)
	resp := decodeSeed(t, postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 1, APIVersion: 3}))
	require.Equal(t, uint32(3), resp.APIVersion)
	require.Nil(t, resp.Voucher)
}

// TestDelegateSeed_VoucherIssuanceLog: every voucher issued is logged at info
// with sealerId, epoch, kmsKeyVersion, pubkey hash and notAfter (ruling 4′,
// the registrar's audit trail).
func TestDelegateSeed_VoucherIssuanceLog(t *testing.T) {
	api, logs, _ := voucherSeedAPI(t, 0)
	resp := decodeSeed(t, postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 2, APIVersion: 3}))
	priv, err := delegatekeys.DeriveKey(resp.Seed, 2, 0)
	require.NoError(t, err)
	hash, err := delegatekeys.PubkeyHashHex(&priv.PublicKey)
	require.NoError(t, err)

	var line string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, `"msg":"delegate key voucher issued"`) {
			line = l
		}
	}
	require.NotEmpty(t, line, "issuance is logged")
	for _, want := range []string{
		`"level":"INFO"`,
		`"sealerId":"sealer-a"`,
		`"epoch":2`,
		`"kmsKeyVersion":"projects/p/locations/l/keyRings/r/cryptoKeys/delegate-seed/cryptoKeyVersions/2"`,
		`"pubkeyHash":"` + hash + `"`,
		// The default TTL applies when the config leaves it zero.
		`"notAfter":` + strconv.FormatInt(testNow.Add(defaultDelegateKeyVoucherTTL).Unix(), 10),
	} {
		require.Contains(t, line, want)
	}
}

// TestDelegateSeed_V3VoucherReachesOutbox: the outbox registers with the
// voucher the sealer was given, not one it signs itself.
func TestDelegateSeed_V3VoucherReachesOutbox(t *testing.T) {
	logs := &syncBuffer{}
	api := NewAPI(slog.New(slog.NewJSONHandler(logs, nil)), Config{
		AppToken:                 "app-token",
		DelegateSeedMacKey:       "projects/p/locations/l/keyRings/r/cryptoKeys/delegate-seed",
		DelegateSeedSealers:      []string{"sealer-a"},
		RegistrarVoucherKey:      "projects/p/locations/l/keyRings/r/cryptoKeys/registrar-voucher",
		DelegationCoordinatorURL: "https://coordinator.invalid",
	})
	api.macSignOverride = fakeMacSign(nil)
	api.getDelegateSeedKeyOverride = fakeDelegateSeedKey(goodMacKey, nil)
	require.NoError(t, api.probeDelegateSeedKey(context.Background()))
	_, signer, kid := registrarKey(t)
	signs := 0
	api.signVoucherOverride = func(_ context.Context, c DelegateKeyVoucherClaims) ([]byte, error) {
		signs++
		return BuildDelegateKeyVoucherWithSigner(c, kid, signer)
	}
	var posted RegisterDelegateKeysBody
	api.registrations.post = func(_ context.Context, body RegisterDelegateKeysBody) registrationOutcome {
		posted = body
		return registrationOutcome{status: http.StatusOK}
	}
	resp := decodeSeed(t, postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 1, APIVersion: 3}))
	api.registrations.attempt(context.Background(), api.registrations.next())
	require.Equal(t, 1, signs, "one voucher per seed request")
	require.Len(t, posted.Keys, 1)
	require.Equal(t, base64.StdEncoding.EncodeToString(resp.Voucher), posted.Keys[0].Voucher)
}
