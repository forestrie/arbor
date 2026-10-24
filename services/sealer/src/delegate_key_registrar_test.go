package sealer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// The assertion body matches the coordinator's RegisterDelegateKeysRequest
// (canopy delegation-coordinator types/register-delegate-keys-request.ts):
// JSON, one key, base64 COSE_Key and voucher, notAfter = voucher claim 4.
func TestCoordinatorRegistrar_BodyShape(t *testing.T) {
	var gotBody []byte
	var gotPath, gotAuth, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotCT = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"registered":1,"retired":0,"shards":4}`)
	}))
	t.Cleanup(srv.Close)
	logger, _ := NewLogger(0)
	reg := coordinatorDelegateKeyRegistrar{baseURL: srv.URL + "/", token: "coord", httpClient: NewHTTPClient(logger)}

	notAfter := time.Unix(1_900_000_000, 0)
	key := registerDelegateKeyEntry{
		Alg: "ES256", PublicKey: base64.StdEncoding.EncodeToString([]byte{0xa5, 1}),
		Epoch: 3, NotAfter: notAfter.Unix(), Voucher: base64.StdEncoding.EncodeToString([]byte{0x84}),
	}
	if res := reg.assert(context.Background(), "sealer-a", key); res.kind != assertOK {
		t.Fatalf("result = %+v", res)
	}
	if gotPath != "/api/sealer/delegate-keys" || gotAuth != "Bearer coord" || gotCT != "application/json" {
		t.Fatalf("path=%q auth=%q ct=%q", gotPath, gotAuth, gotCT)
	}
	var body map[string]any
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	keys := body["keys"].([]any)
	if body["sealerId"] != "sealer-a" || len(keys) != 1 {
		t.Fatalf("body = %s", gotBody)
	}
	k := keys[0].(map[string]any)
	if k["alg"] != "ES256" || k["publicKey"] != "pQE=" || k["epoch"] != float64(3) ||
		k["notAfter"] != float64(1_900_000_000) || k["voucher"] != "hA==" {
		t.Fatalf("key = %v", k)
	}
}

// Each coordinator answer maps to the outcome slice 05 change 3 names.
func TestCoordinatorRegistrar_Outcomes(t *testing.T) {
	var status atomic.Int32
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	t.Cleanup(srv.Close)
	logger, _ := NewLogger(0)
	reg := coordinatorDelegateKeyRegistrar{baseURL: srv.URL, token: "x", httpClient: NewHTTPClient(logger)}

	cases := []struct {
		status int
		body   string
		want   assertKind
	}{
		{200, `{}`, assertOK},
		{201, `{}`, assertOK},
		{409, `{"title":"Conflict","detail":"sealer s epoch 3 already has delegate key aa; refusing bb"}`, assertConflict},
		{410, `{"title":"Gone","detail":"delegate key tombstoned"}`, assertTombstoned},
		// A fresh voucher fixes these (canopy post-delegate-keys.ts and
		// delegation-store.ts parseDelegateKeyBatch).
		{400, `{"type":"about:blank","title":"Invalid voucher","detail":"delegate-key voucher failed verification (expired)"}`, assertVoucherRefused},
		{400, `{"type":"about:blank","title":"Invalid voucher","detail":"delegate-key voucher failed verification (signature)"}`, assertVoucherRefused},
		{400, `{"type":"about:blank","title":"Invalid request","status":400,"detail":"notAfter must be in the future"}`, assertVoucherRefused},
		// Malformed bodies: a fresh voucher does not fix them.
		{400, `{"type":"about:blank","title":"Invalid request","detail":"publicKey and voucher must be valid base64"}`, assertRetry},
		{400, `{"type":"about:blank","title":"Invalid request","status":400,"detail":"voucher must be valid base64"}`, assertRetry},
		{400, `{"type":"about:blank","title":"Invalid request","status":400,"detail":"voucher is required"}`, assertRetry},
		{400, `{"title":"Invalid request","detail":"epoch must be >= 1"}`, assertRetry},
		{401, `{}`, assertRetry},
		{503, `not json`, assertRetry},
	}
	for _, c := range cases {
		status.Store(int32(c.status))
		body.Store(c.body)
		res := reg.assert(context.Background(), "s", registerDelegateKeyEntry{Epoch: 3})
		if res.kind != c.want {
			t.Errorf("status %d %s: kind = %v, want %v", c.status, c.body, res.kind, c.want)
		}
		if c.status == 409 && res.detail == "" {
			t.Error("409 detail must reach the log")
		}
	}

	srv.Close()
	if res := reg.assert(context.Background(), "s", registerDelegateKeyEntry{Epoch: 3}); res.kind != assertRetry || res.err == nil {
		t.Fatalf("transport error: %+v", res)
	}
}
