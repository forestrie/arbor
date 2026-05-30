package sealer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/fxamacker/cbor/v2"
)

// These tests prove the plan-0003 two-seam BYOK architecture without
// requiring deployed Univocity contracts. The Sealer is wired to:
//
//   - HTTPTrustRootClient -> fake trust-root server (CBOR x,y of a
//     test-owned root key; non-Custodian)
//   - HTTPDelegationIssuer -> fake delegation issuer server that signs
//     certificates with the same test-owned root key (non-Custodian)
//
// Sealer fetches the root over HTTP, fetches the delegation over HTTP from
// a *different* URL, and verifies one against the other.

const (
	byokIssuerToken = "issuer-token"
	byokDomain      = "forestrie.test.delegation"
	byokChainID     = "31337"
	byokContract    = "0x0000000000000000000000000000000000000001"
)

func TestRequestLogDelegationLease_BYOKHTTPTrustRoot(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := "0123456789abcdef0123456789abcdef"

	var trustRootCalledFor string
	trustSrv := newBYOKTrustRootServer(t, logID, &rootPriv.PublicKey, byokDomain, byokChainID, byokContract, &trustRootCalledFor)
	defer trustSrv.Close()

	var seen delegationcert.DelegationIssueRequest
	issuerSrv := newBYOKIssuerServer(t, rootPriv, logID, &seen)
	defer issuerSrv.Close()

	trustRoot := &HTTPTrustRootClient{
		BaseURL:    trustSrv.URL,
		HTTPClient: NewHTTPClient(nil),
	}

	lease, err := RequestLogDelegationLease(
		context.Background(),
		NewHTTPClient(nil),
		trustRoot,
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
	if err != nil {
		t.Fatalf("expected BYOK lease, got %v", err)
	}
	if len(lease.CertBytes) == 0 {
		t.Fatal("expected lease certificate")
	}

	if trustRootCalledFor != logID {
		t.Fatalf("trust root not fetched for log: got %q want %q", trustRootCalledFor, logID)
	}
	if seen.Domain != byokDomain {
		t.Fatalf("domain not propagated: %q", seen.Domain)
	}
	if seen.ChainID != byokChainID {
		t.Fatalf("chain id not propagated: %q", seen.ChainID)
	}
	if seen.ContractAddress != byokContract {
		t.Fatalf("contract address not propagated: %q", seen.ContractAddress)
	}
}

func TestRequestLogDelegationLease_BYOKHTTPRejectsWrongRoot(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Trust-root advertises a DIFFERENT pubkey from the one the issuer signs with.
	wrongRootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := "1123456789abcdef0123456789abcdef"

	trustSrv := newBYOKTrustRootServer(t, logID, &wrongRootPriv.PublicKey, "", "", "", nil)
	defer trustSrv.Close()

	issuerSrv := newBYOKIssuerServer(t, rootPriv, logID, nil)
	defer issuerSrv.Close()

	_, err = RequestLogDelegationLease(
		context.Background(),
		NewHTTPClient(nil),
		&HTTPTrustRootClient{BaseURL: trustSrv.URL, HTTPClient: NewHTTPClient(nil)},
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
		t.Fatal("expected wrong trust root to fail verification")
	}
}

func TestRequestLogDelegationLease_BYOKHTTPRejectsWrongLog(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := "2123456789abcdef0123456789abcdef"

	trustSrv := newBYOKTrustRootServer(t, logID, &rootPriv.PublicKey, "", "", "", nil)
	defer trustSrv.Close()

	// Issuer signs a certificate for a different log id than the caller asked for.
	issuerSrv := newBYOKIssuerServer(t, rootPriv, "ffffffffffffffffffffffffffffffff", nil)
	defer issuerSrv.Close()

	_, err = RequestLogDelegationLease(
		context.Background(),
		NewHTTPClient(nil),
		&HTTPTrustRootClient{BaseURL: trustSrv.URL, HTTPClient: NewHTTPClient(nil)},
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

// newBYOKTrustRootServer stands up a fake trust-root HTTP service that
// returns the CBOR plan-0003 shape for the given log id.
//
// If gotLog is non-nil it captures the log id seen by the handler so the
// caller can assert Sealer hit the trust-root URL for the expected log.
func newBYOKTrustRootServer(
	t *testing.T,
	logIDHex string,
	pub *ecdsa.PublicKey,
	domain, chainID, contract string,
	gotLog *string,
) *httptest.Server {
	t.Helper()
	logIDBytes, err := hex.DecodeString(logIDHex)
	if err != nil {
		t.Fatalf("decode log id hex: %v", err)
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)

	prefix := "/api/logs/"
	suffix := "/signing-key"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, suffix) {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Accept") != "application/cbor" {
			t.Errorf("trust root: missing Accept: application/cbor (got %q)", r.Header.Get("Accept"))
			http.Error(w, "bad accept", http.StatusBadRequest)
			return
		}
		seenLog := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), suffix)
		if gotLog != nil {
			*gotLog = seenLog
		}
		if seenLog != logIDHex {
			http.Error(w, fmt.Sprintf("unknown log %s", seenLog), http.StatusNotFound)
			return
		}

		body, err := cbor.Marshal(TrustRootResponse{
			LogID:           logIDBytes,
			Alg:             "ES256",
			X:               x,
			Y:               y,
			ChainID:         chainID,
			ContractAddress: contract,
			Domain:          domain,
		})
		if err != nil {
			t.Errorf("encode trust root: %v", err)
			http.Error(w, "encode", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(body)
	}))
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
