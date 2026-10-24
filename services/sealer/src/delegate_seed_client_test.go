package sealer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// fakeCustodianServer is a delegate-seed apiVersion 3 custodian (devdocs
// plan-2609-12 slice 07): deterministic per-epoch seeds, and beside each a
// registrar voucher {1: sealerId, 2: epoch, 3: COSE_Key, 4: notAfter}
// signed with a throwaway ES256 key. Fields are read under mu per request so
// a test can change the answers while the sealer runs.
type fakeCustodianServer struct {
	t   *testing.T
	srv *httptest.Server

	mu         sync.Mutex
	retired    map[uint32]bool // 409
	failing    map[uint32]bool // 500
	noVoucher  map[uint32]bool // v3 answer without a voucher
	wrongKey   map[uint32]bool // voucher binds a key other than the seed's
	seedSalt   string          // changes every derived key
	apiVersion uint32
	ttl        time.Duration
	down       bool // every request 503
	requests   []delegateSeedRequest
	lastAuth   string
	registrar  *ecdsa.PrivateKey
	// override, when set, answers instead of the defaults above.
	override func(w http.ResponseWriter, req delegateSeedRequest)
}

func newFakeCustodian(t *testing.T) *fakeCustodianServer {
	t.Helper()
	reg, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCustodianServer{
		t: t, retired: map[uint32]bool{}, failing: map[uint32]bool{},
		noVoucher: map[uint32]bool{}, wrongKey: map[uint32]bool{},
		apiVersion: delegateSeedAPIVersion, ttl: 24 * time.Hour, registrar: reg,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCustodianServer) set(fn func(f *fakeCustodianServer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeCustodianServer) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeCustodianServer) seedFor(epoch uint32) []byte {
	s := sha256.Sum256([]byte(fmt.Sprintf("seed/%s/%d", f.seedSalt, epoch)))
	return s[:]
}

func (f *fakeCustodianServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var req delegateSeedRequest
	body, _ := io.ReadAll(r.Body)
	_ = cbor.Unmarshal(body, &req)
	f.requests = append(f.requests, req)
	f.lastAuth = r.Header.Get("Authorization")
	if f.override != nil {
		f.override(w, req)
		return
	}
	switch {
	case f.down:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	case f.retired[req.Epoch]:
		w.WriteHeader(http.StatusConflict)
		return
	case f.failing[req.Epoch]:
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	seed := f.seedFor(req.Epoch)
	resp := delegateSeedResponse{Seed: seed, KMSKeyVersion: fmt.Sprintf("k/cryptoKeyVersions/%d", req.Epoch), APIVersion: f.apiVersion}
	if f.apiVersion >= 3 && !f.noVoucher[req.Epoch] {
		keySeed := seed
		if f.wrongKey[req.Epoch] {
			keySeed = sha256.New().Sum(seed)
		}
		k, err := deriveDelegateKey(keySeed, req.Epoch, 0)
		if err != nil {
			f.t.Errorf("derive: %v", err)
		}
		notAfter := time.Now().Add(f.ttl).Unix()
		resp.Voucher = f.voucher(req.SealerID, req.Epoch, &k.PublicKey, notAfter)
		resp.VoucherNotAfter = uint64(notAfter)
	}
	out, _ := cbor.Marshal(resp)
	w.Header().Set("Content-Type", "application/cbor")
	_, _ = w.Write(out)
}

// voucher builds an untagged COSE_Sign1 registrar voucher, as the custodian
// does (arbor services/custodian/src/voucher.go).
func (f *fakeCustodianServer) voucher(sealerID string, epoch uint32, pub *ecdsa.PublicKey, notAfter int64) []byte {
	coseKey, err := delegateCoseKeyBytes(pub)
	if err != nil {
		f.t.Fatal(err)
	}
	payload, err := canonicalCBOR.Marshal(delegateKeyVoucherClaims{SealerID: sealerID, Epoch: epoch, Key: coseKey, NotAfter: uint64(notAfter)})
	if err != nil {
		f.t.Fatal(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, f.registrar)
	if err != nil {
		f.t.Fatal(err)
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected = cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmES256}
	msg.Payload = payload
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		f.t.Fatal(err)
	}
	u := cose.UntaggedSign1Message(*msg)
	b, err := u.MarshalCBOR()
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func (f *fakeCustodianServer) provider() custodianSeedProvider {
	logger, _ := NewLogger(0)
	return custodianSeedProvider{baseURL: f.srv.URL, token: "t", sealerID: "sealer-a", httpClient: NewHTTPClient(logger), logger: logger}
}

// fakeCustodian is the fixed-answer form most load tests need.
func fakeCustodian(t *testing.T, retired, failing map[uint32]bool) custodianSeedProvider {
	t.Helper()
	f := newFakeCustodian(t)
	for e := range retired {
		f.retired[e] = true
	}
	for e := range failing {
		f.failing[e] = true
	}
	return f.provider()
}

// The sealer asks for apiVersion 3 with bearer auth, and gets back the seed
// and the voucher with its notAfter (claim 4).
func TestCustodianSeedProvider_RequestsV3AndDecodesVoucher(t *testing.T) {
	f := newFakeCustodian(t)
	got, err := f.provider().Seed(context.Background(), 7)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !bytes.Equal(got.Seed, f.seedFor(7)) {
		t.Fatal("seed mismatch")
	}
	if req := f.requests[0]; req.SealerID != "sealer-a" || req.Epoch != 7 || req.APIVersion != 3 {
		t.Fatalf("request = %+v, want apiVersion 3", req)
	}
	if f.lastAuth != "Bearer t" {
		t.Fatalf("auth = %q", f.lastAuth)
	}
	v := got.Voucher
	if v == nil || v.Epoch != 7 || v.SealerID != "sealer-a" || len(v.Raw) == 0 {
		t.Fatalf("voucher = %+v", v)
	}
	if d := time.Until(v.NotAfter); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("voucher notAfter %v, want about 24h out", v.NotAfter)
	}
}

// A custodian below apiVersion 3 is refused, not as retired, naming slice 07.
func TestCustodianSeedProvider_RequiresAPIVersion3(t *testing.T) {
	for _, v := range []uint32{0, 1, 2} {
		f := newFakeCustodian(t)
		f.apiVersion = v
		_, err := f.provider().Seed(context.Background(), 4)
		if err == nil || !strings.Contains(err.Error(), "custodian predates plan-2609-12 slice 07") {
			t.Fatalf("apiVersion %d: err = %v", v, err)
		}
		if errors.Is(err, errDelegateSeedEpochRetired) {
			t.Fatalf("apiVersion mismatch must not be reported as retired: %v", err)
		}
	}
}

// A version-3 answer without a voucher (the custodian failed to sign one)
// still yields the seed, so the key installs.
func TestCustodianSeedProvider_V3WithoutVoucher(t *testing.T) {
	f := newFakeCustodian(t)
	f.noVoucher[3] = true
	got, err := f.provider().Seed(context.Background(), 3)
	if err != nil || len(got.Seed) == 0 || got.Voucher != nil {
		t.Fatalf("got %+v, %v; want seed without voucher", got, err)
	}
}

// A voucher for another sealer or epoch is refused.
func TestCustodianSeedProvider_VoucherForOtherSealerRefused(t *testing.T) {
	f := newFakeCustodian(t)
	p := f.provider()
	p.sealerID = "sealer-b"
	f.override = func(w http.ResponseWriter, _ delegateSeedRequest) {
		k, _ := deriveDelegateKey(f.seedFor(2), 2, 0)
		out, _ := cbor.Marshal(delegateSeedResponse{
			Seed: f.seedFor(2), APIVersion: 3,
			Voucher: f.voucher("sealer-a", 2, &k.PublicKey, time.Now().Add(time.Hour).Unix()),
		})
		_, _ = w.Write(out)
	}
	if _, err := p.Seed(context.Background(), 2); err == nil || !strings.Contains(err.Error(), "voucher") {
		t.Fatalf("err = %v, want voucher refusal", err)
	}
}

// A voucher binding a key other than the one the seed derives is refused,
// so nothing loads from that response.
func TestLoadDelegateKeys_VoucherBindingAnotherKeyRefused(t *testing.T) {
	f := newFakeCustodian(t)
	f.wrongKey[5] = true
	_, err := LoadDelegateKeys(context.Background(), f.provider(), 5)
	if err == nil || !strings.Contains(err.Error(), "voucher") {
		t.Fatalf("err = %v, want voucher binding refusal", err)
	}
}

// Each loaded key carries the voucher that binds it.
func TestLoadDelegateKeys_CarriesVouchers(t *testing.T) {
	f := newFakeCustodian(t)
	keys, err := LoadDelegateKeys(context.Background(), f.provider(), 5)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(keys.entries) != 2 {
		t.Fatalf("entries = %d", len(keys.entries))
	}
	for _, e := range keys.entries {
		want, _ := delegateCoseKeyBytes(&e.priv.PublicKey)
		if e.voucher == nil || e.voucher.Epoch != e.epoch || !bytes.Equal(e.voucher.CoseKey, want) {
			t.Fatalf("epoch %d voucher = %+v", e.epoch, e.voucher)
		}
	}
}

// TestLoadDelegateKeys_RetiredPrevious: once the operator disables the N-1
// key version (plan-2609-11 runbook step 4) the sealer must still boot, with
// epoch N alone.
func TestLoadDelegateKeys_RetiredPrevious(t *testing.T) {
	p := fakeCustodian(t, map[uint32]bool{4: true}, nil)
	keys, err := LoadDelegateKeys(context.Background(), p, 5)
	if err != nil {
		t.Fatalf("load with retired N-1 must succeed: %v", err)
	}
	if keys.Current() == nil || len(keys.byPubkeyHash) != 1 {
		t.Fatalf("want epoch N only; got %d keys, current=%v", len(keys.byPubkeyHash), keys.Current() != nil)
	}
	if !keys.PreviousRetired() {
		t.Fatal("PreviousRetired must report the refused N-1")
	}
}

// A retired CURRENT epoch is an operator error (the sealer was bumped to an
// epoch whose version does not exist or is disabled): fail the load.
func TestLoadDelegateKeys_RetiredCurrentFails(t *testing.T) {
	p := fakeCustodian(t, map[uint32]bool{5: true}, nil)
	if _, err := LoadDelegateKeys(context.Background(), p, 5); err == nil {
		t.Fatal("retired current epoch must fail the load")
	}
}

// A transient failure for N-1 is NOT retirement: fail the load so the boot
// retry runs again rather than silently dropping the overlap.
func TestLoadDelegateKeys_TransientPreviousFails(t *testing.T) {
	p := fakeCustodian(t, nil, map[uint32]bool{4: true})
	_, err := LoadDelegateKeys(context.Background(), p, 5)
	if err == nil {
		t.Fatal("transient N-1 failure must fail the load")
	}
	if errors.Is(err, errDelegateSeedEpochRetired) {
		t.Fatal("a 500 must not be reported as retired")
	}
}

func TestCustodianSeedProvider_RetiredIs409(t *testing.T) {
	p := fakeCustodian(t, map[uint32]bool{3: true}, nil)
	_, err := p.Seed(context.Background(), 3)
	if !errors.Is(err, errDelegateSeedEpochRetired) {
		t.Fatalf("409 must map to errDelegateSeedEpochRetired, got %v", err)
	}
}

// A non-200 answer logs the custodian's CBOR problem title and detail, e.g.
// the 501 while the custodian has not verified its MAC key (ruling 2).
func TestCustodianSeedProvider_ProblemDetailInError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := cbor.Marshal(map[string]any{"title": "misconfigured", "status": 501, "detail": "delegate seed MAC key not verified"})
		w.Header().Set("Content-Type", "application/problem+cbor")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	logger, _ := NewLogger(0)
	p := custodianSeedProvider{baseURL: srv.URL, token: "t", sealerID: "sealer-a", httpClient: NewHTTPClient(logger)}
	_, err := p.Seed(context.Background(), 2)
	if err == nil || !strings.Contains(err.Error(), "status=501") ||
		!strings.Contains(err.Error(), "misconfigured") || !strings.Contains(err.Error(), "not verified") {
		t.Fatalf("err = %v", err)
	}
}
