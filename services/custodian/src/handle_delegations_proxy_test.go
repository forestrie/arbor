package custodian

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

func TestHandleDelegations_proxiesWhenWalletManaged(t *testing.T) {
	logBytes := logIDBytes16(t)
	logHex, _ := logIDHexFromWire(logBytes)
	var coordinatorIssue bool
	coord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/logs/"+logHex+"/signing-route":
			_ = json.NewEncoder(w).Encode(map[string]string{"mode": "wallet"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/delegations":
			coordinatorIssue = true
			resp := delegationcert.DelegationIssueResponse{
				IssuedAt:    1,
				ExpiresAt:   999,
				Certificate: []byte{0x01},
			}
			b, _ := custodianCBORem.Marshal(resp)
			w.Header().Set("Content-Type", "application/cbor")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer coord.Close()

	logger, _ := NewLogger(0)
	api := NewAPI(logger, Config{
		AppToken:                 "app-token",
		DelegationCoordinatorURL: coord.URL,
	})

	body, _ := custodianCBORem.Marshal(delegationcert.DelegationIssueRequest{
		LogID:              logBytes,
		DelegatedPublicKey: []byte{1},
		Algorithm:          "ES256",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/delegations", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("Authorization", "Bearer app-token")
	rec := httptest.NewRecorder()

	api.handleDelegations(rec, req)

	if !coordinatorIssue {
		t.Fatal("expected coordinator issue call for wallet-managed log")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out delegationcert.DelegationIssueResponse
	if err := custodianCBORdm.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Certificate) != 1 {
		t.Fatalf("cert=%v", out.Certificate)
	}
}

func TestProxyDelegationIssue_forwardsCBOR(t *testing.T) {
	coord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/delegations" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		var req delegationcert.DelegationIssueRequest
		if err := custodianCBORdm.Unmarshal(body, &req); err != nil {
			t.Fatal(err)
		}
		resp := delegationcert.DelegationIssueResponse{Certificate: []byte{0xab}}
		b, _ := custodianCBORem.Marshal(resp)
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(b)
	}))
	defer coord.Close()

	logger, _ := NewLogger(0)
	api := NewAPI(logger, Config{
		AppToken:                 "tok",
		DelegationCoordinatorURL: coord.URL,
	})

	in, _ := custodianCBORem.Marshal(delegationcert.DelegationIssueRequest{
		LogID: logIDBytes16(t),
	})
	out, st, err := api.proxyDelegationIssue(t.Context(), in, "Bearer tok")
	if err != nil || st != http.StatusOK {
		t.Fatalf("err=%v st=%d", err, st)
	}
	if len(out.Certificate) != 1 || out.Certificate[0] != 0xab {
		t.Fatalf("cert=%v", out.Certificate)
	}
}

func logIDBytes16(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, 16)
	for i := range raw {
		raw[i] = byte(i)
	}
	hex, err := logIDHexFromWire(raw)
	if err != nil {
		t.Fatal(err)
	}
	_ = hex
	return raw
}
