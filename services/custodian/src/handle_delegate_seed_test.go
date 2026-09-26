package custodian

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func delegateSeedAPI(t *testing.T) *API {
	t.Helper()
	logger, _ := NewLogger(0)
	api := NewAPI(logger, Config{
		AppToken:            "app-token",
		DelegateSeedMacKey:  "projects/p/locations/l/keyRings/r/cryptoKeys/delegate-seed",
		DelegateSeedSealers: []string{"sealer-a", "sealer-b"},
	})
	api.macSignOverride = fakeMacSign(nil)
	return api
}

// fakeMacSign is a deterministic fake KMS: the HMAC key is derived from the
// CryptoKeyVersion name, mirroring MacSign's determinism per key version and
// its distinctness across versions. Versions listed in retired are refused the
// way KMS refuses a disabled or destroyed version.
func fakeMacSign(retired map[string]bool) func(context.Context, string, []byte) ([]byte, string, error) {
	return func(_ context.Context, versionName string, data []byte) ([]byte, string, error) {
		if retired[versionName] {
			return nil, "", fmt.Errorf("%w: %s", errDelegateSeedEpochRetired, versionName)
		}
		mac := hmac.New(sha256.New, []byte("test-kms-mac-key/"+versionName))
		mac.Write(data)
		return mac.Sum(nil), versionName, nil
	}
}

func decodeSeed(t *testing.T, rec *httptest.ResponseRecorder) DelegateSeedResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	var resp DelegateSeedResponse
	if err := cbor.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func postDelegateSeed(t *testing.T, api *API, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := cbor.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/delegate-seed", bytes.NewReader(raw))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	api.handleDelegateSeed(rec, req)
	return rec
}

func TestDelegateSeed_RequiresAppToken(t *testing.T) {
	api := delegateSeedAPI(t)
	if rec := postDelegateSeed(t, api, "", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 1}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", rec.Code)
	}
	if rec := postDelegateSeed(t, api, "wrong", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 1}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", rec.Code)
	}
}

func TestDelegateSeed_SealerAllowlist(t *testing.T) {
	api := delegateSeedAPI(t)
	if rec := postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "intruder", Epoch: 1}); rec.Code != http.StatusForbidden {
		t.Fatalf("unlisted sealer: got %d, want 403", rec.Code)
	}
}

func TestDelegateSeed_ValidatesEpochAndConfig(t *testing.T) {
	api := delegateSeedAPI(t)
	if rec := postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 0}); rec.Code != http.StatusBadRequest {
		t.Fatalf("epoch 0: got %d, want 400", rec.Code)
	}
	logger, _ := NewLogger(0)
	unconfigured := NewAPI(logger, Config{AppToken: "app-token"})
	if rec := postDelegateSeed(t, unconfigured, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 1}); rec.Code != http.StatusNotImplemented {
		t.Fatalf("unconfigured: got %d, want 501", rec.Code)
	}
	// A pinned version would override the epoch's choice of version.
	pinned := NewAPI(logger, Config{
		AppToken:            "app-token",
		DelegateSeedMacKey:  "projects/p/locations/l/keyRings/r/cryptoKeys/delegate-seed/cryptoKeyVersions/1",
		DelegateSeedSealers: []string{"sealer-a"},
	})
	pinned.macSignOverride = fakeMacSign(nil)
	if rec := postDelegateSeed(t, pinned, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 1}); rec.Code != http.StatusNotImplemented {
		t.Fatalf("versioned key config: got %d, want 501", rec.Code)
	}
}

// TestDelegateSeed_EpochIsKeyVersion pins the plan-2609-11 binding: epoch e is
// signed under CryptoKeyVersion e of the configured MAC key, and the version
// used is reported back to the sealer.
func TestDelegateSeed_EpochIsKeyVersion(t *testing.T) {
	api := delegateSeedAPI(t)
	var gotVersion string
	inner := api.macSignOverride
	api.macSignOverride = func(ctx context.Context, versionName string, data []byte) ([]byte, string, error) {
		gotVersion = versionName
		return inner(ctx, versionName, data)
	}
	resp := decodeSeed(t, postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 10}))
	want := "projects/p/locations/l/keyRings/r/cryptoKeys/delegate-seed/cryptoKeyVersions/10"
	if gotVersion != want {
		t.Fatalf("MacSign version = %q, want %q", gotVersion, want)
	}
	if resp.KMSKeyVersion != want {
		t.Fatalf("response kmsKeyVersion = %q, want %q", resp.KMSKeyVersion, want)
	}
}

// TestDelegateSeed_RotationKeepsPreviousEpoch is the property FOR-584 and the
// ADR-0050 "As implemented" note were about: creating a new key version (a
// rotation) must not change the seed of an earlier epoch, so certificates
// bound to the epoch N-1 key stay usable through the N/N-1 overlap.
func TestDelegateSeed_RotationKeepsPreviousEpoch(t *testing.T) {
	api := delegateSeedAPI(t)
	before := decodeSeed(t, postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 1}))
	// "Rotation": version 2 now exists and the sealer bumps to epoch 2.
	after2 := decodeSeed(t, postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 2}))
	after1 := decodeSeed(t, postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 1}))
	if !bytes.Equal(before.Seed, after1.Seed) {
		t.Fatal("epoch 1 seed changed after a new key version appeared")
	}
	if bytes.Equal(after2.Seed, after1.Seed) {
		t.Fatal("epoch 2 must derive under a different version than epoch 1")
	}
	if after1.KMSKeyVersion == after2.KMSKeyVersion {
		t.Fatal("epochs 1 and 2 must report different key versions")
	}
}

// TestDelegateSeed_RetiredEpoch: a disabled or destroyed version is a 409 the
// sealer can treat as final for this boot, not a 502 it should retry.
func TestDelegateSeed_RetiredEpoch(t *testing.T) {
	api := delegateSeedAPI(t)
	api.macSignOverride = fakeMacSign(map[string]bool{
		"projects/p/locations/l/keyRings/r/cryptoKeys/delegate-seed/cryptoKeyVersions/1": true,
	})
	if rec := postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 1}); rec.Code != http.StatusConflict {
		t.Fatalf("retired epoch: got %d, want 409: %s", rec.Code, rec.Body.String())
	}
	decodeSeed(t, postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 2}))
	// Any other KMS failure stays a 502.
	api.macSignOverride = func(context.Context, string, []byte) ([]byte, string, error) {
		return nil, "", fmt.Errorf("kms MacSign: unavailable")
	}
	if rec := postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 2}); rec.Code != http.StatusBadGateway {
		t.Fatalf("kms failure: got %d, want 502", rec.Code)
	}
}

// TestDelegateSeed_FixedPrefixAndDeterminism pins the two load-bearing
// properties (ADR-0050): the MAC input is the fixed server-side prefix plus
// (sealerId, epoch) only — never caller-supplied bytes — and the derivation
// is deterministic so delegate keys (and every advance certificate bound to
// them) survive restarts.
func TestDelegateSeed_FixedPrefixAndDeterminism(t *testing.T) {
	api := delegateSeedAPI(t)
	var gotData []byte
	inner := api.macSignOverride
	api.macSignOverride = func(ctx context.Context, keyName string, data []byte) ([]byte, string, error) {
		gotData = append([]byte(nil), data...)
		return inner(ctx, keyName, data)
	}

	rec1 := postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 3})
	if rec1.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec1.Code, rec1.Body.String())
	}
	if want := "forestrie/sealer-delegate-seed/v1/sealer-a/3"; string(gotData) != want {
		t.Fatalf("MAC input = %q, want %q (fixed prefix)", gotData, want)
	}

	var resp1, resp2 DelegateSeedResponse
	if err := cbor.Unmarshal(rec1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp1.Seed) != sha256.Size {
		t.Fatalf("seed length = %d, want %d", len(resp1.Seed), sha256.Size)
	}

	rec2 := postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 3})
	if err := cbor.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(resp1.Seed, resp2.Seed) {
		t.Fatal("same (sealerId, epoch) must derive the same seed")
	}

	// Different epoch ⇒ different seed (rotation actually rotates).
	rec3 := postDelegateSeed(t, api, "app-token", DelegateSeedRequest{SealerID: "sealer-a", Epoch: 4})
	var resp3 DelegateSeedResponse
	if err := cbor.Unmarshal(rec3.Body.Bytes(), &resp3); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bytes.Equal(resp1.Seed, resp3.Seed) {
		t.Fatal("epoch bump must change the seed")
	}
}
