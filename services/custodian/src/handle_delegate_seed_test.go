package custodian

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
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
	// Deterministic fake KMS MAC: HMAC over a fixed test key — mirrors
	// MacSign's determinism per key version.
	api.macSignOverride = func(_ context.Context, keyName string, data []byte) ([]byte, string, error) {
		mac := hmac.New(sha256.New, []byte("test-kms-mac-key"))
		mac.Write(data)
		return mac.Sum(nil), keyName + "/cryptoKeyVersions/1", nil
	}
	return api
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
