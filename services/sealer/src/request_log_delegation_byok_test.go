package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/fxamacker/cbor/v2"
)

// The sealer takes a log's root key from univocity and its certificate from
// a separate delegation issuer (non-Custodian here, runner-owned), and
// verifies one against the other. The issuer helpers below are shared with
// the univocity authority tests.

const byokIssuerToken = "issuer-token"

func TestRequestLogDelegationLease_BYOKRejectsCertificateForAnotherLog(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := "2123456789abcdef0123456789abcdef"

	authSrv := newAuthorityServer(t, &rootPriv.PublicKey, 0)
	defer authSrv.Close()

	// Issuer signs a certificate for a different log id than the caller asked for.
	issuerSrv := newBYOKIssuerServer(t, rootPriv, "ffffffffffffffffffffffffffffffff", nil)
	defer issuerSrv.Close()

	_, err = requestLeaseForTest(t,
		context.Background(),
		NewHTTPClient(nil),
		&HTTPAuthorityResolver{BaseURL: authSrv.URL, HTTPClient: NewHTTPClient(nil)},
		&HTTPDelegationIssuer{
			BaseURL:    issuerSrv.URL,
			Token:      byokIssuerToken,
			HTTPClient: NewHTTPClient(nil),
		},
		"secp256r1",
		30*time.Minute,
		logID,
		7,
		21,
	)
	if err == nil {
		t.Fatal("expected wrong log certificate to fail verification")
	}
}

// newBYOKIssuerServer stands up a fake delegation issuer that signs the
// returned certificate with rootPriv (non-Custodian, runner-owned).
func newBYOKIssuerServer(
	t *testing.T,
	rootPriv *ecdsa.PrivateKey,
	certLogID string,
	seen *delegationcert.DelegationIssueRequest,
) *httptest.Server {
	t.Helper()
	kid, err := kidFromECDSAPublicKey(&rootPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/delegations" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+byokIssuerToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req delegationcert.DelegationIssueRequest
		if err := cbor.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if seen != nil {
			*seen = req
		}
		delegatedKey, curve, err := delegationcert.ParseDelegatedPublicKeyFromCBOR(req.DelegatedPublicKey)
		if err != nil {
			t.Errorf("parse delegated key: %v", err)
			http.Error(w, "bad delegated key", http.StatusBadRequest)
			return
		}
		issuedAt := uint64(time.Now().Unix())
		expiresAt := issuedAt + 3600
		tbs, err := delegationcert.BuildDelegationToBeSigned(
			curve,
			kid,
			delegationcert.DelegationInput{
				LogID:        certLogID,
				MmrStart:     req.MMRStart,
				MmrEnd:       req.MMREnd,
				DelegatedKey: delegatedKey,
				Constraints:  map[string]any{},
				DelegationID: make([]byte, 16),
				IssuedAt:     issuedAt,
				ExpiresAt:    expiresAt,
			},
		)
		if err != nil {
			t.Errorf("build certificate tbs: %v", err)
			http.Error(w, "build cert", http.StatusInternalServerError)
			return
		}
		rSig, sSig, err := ecdsa.Sign(rand.Reader, rootPriv, tbs.SigStructureDigest)
		if err != nil {
			t.Errorf("sign certificate: %v", err)
			http.Error(w, "sign cert", http.StatusInternalServerError)
			return
		}
		sig := make([]byte, 64)
		rSig.FillBytes(sig[:32])
		sSig.FillBytes(sig[32:])
		cert, err := delegationcert.AssembleDelegationCert(tbs, sig)
		if err != nil {
			t.Errorf("assemble certificate: %v", err)
			http.Error(w, "assemble cert", http.StatusInternalServerError)
			return
		}
		body, err := cbor.Marshal(delegationcert.DelegationIssueResponse{
			Version:     1,
			IssuedAt:    int64(issuedAt),
			ExpiresAt:   int64(expiresAt),
			Certificate: cert,
		})
		if err != nil {
			t.Errorf("encode response: %v", err)
			http.Error(w, "encode response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(body)
	}))
}
