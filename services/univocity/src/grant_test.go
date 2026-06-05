package univocity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fxamacker/cbor/v2"
)

// --- test crypto/CBOR helpers ---

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func pubXY(priv *ecdsa.PrivateKey) (x, y [32]byte) {
	priv.PublicKey.X.FillBytes(x[:])
	priv.PublicKey.Y.FillBytes(y[:])
	return x, y
}

func xyConcat(priv *ecdsa.PrivateKey) []byte {
	x, y := pubXY(priv)
	out := make([]byte, 64)
	copy(out[:32], x[:])
	copy(out[32:], y[:])
	return out
}

func protectedES256(t *testing.T) []byte {
	t.Helper()
	b, err := cbor.Marshal(map[int]interface{}{1: -7})
	if err != nil {
		t.Fatalf("encode protected: %v", err)
	}
	return b
}

func signSign1(t *testing.T, priv *ecdsa.PrivateKey, protected, payload []byte) []byte {
	t.Helper()
	sig := []interface{}{"Signature1", protected, []byte{}, payload}
	sb, err := cbor.Marshal(sig)
	if err != nil {
		t.Fatalf("encode sig structure: %v", err)
	}
	d := sha256.Sum256(sb)
	r, s, err := ecdsa.Sign(rand.Reader, priv, d[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

func buildGrantStatement(t *testing.T, ownerPriv *ecdsa.PrivateKey, g Grant) []byte {
	t.Helper()
	inner := map[int]interface{}{
		grantKeyLogID:      g.LogID[:],
		grantKeyOwnerLogID: g.OwnerLogID[:],
		grantKeyFlags:      g.Flags,
		grantKeyMaxHeight:  g.MaxHeight,
		grantKeyMinGrowth:  g.MinGrowth,
		grantKeyGrantData:  g.GrantData,
	}
	embedded, err := cbor.Marshal(inner)
	if err != nil {
		t.Fatalf("encode grant: %v", err)
	}
	protected := protectedES256(t)
	digest := sha256.Sum256(embedded)
	sig := signSign1(t, ownerPriv, protected, digest[:])
	unprot := map[interface{}]interface{}{
		headerForestrieGrant: embedded,
		headerIdtimestamp:    make([]byte, 8),
	}
	cose := []interface{}{protected, unprot, digest[:], sig}
	out, err := cbor.Marshal(cose)
	if err != nil {
		t.Fatalf("encode cose: %v", err)
	}
	return out
}

func buildGenesisDoc(t *testing.T, r [32]byte, boot *ecdsa.PrivateKey, chainID uint64, addr common.Address) []byte {
	t.Helper()
	x, y := pubXY(boot)
	m := map[int]interface{}{
		coseKeyKty:          coseKtyEc2,
		coseKeyAlg:          coseAlgES256,
		coseEc2Crv:          coseCrvP256,
		coseEc2X:            x[:],
		coseEc2Y:            y[:],
		labelGenesisVersion: genesisSchemaV1,
		labelBootstrapLogID: r[:],
		labelUnivocityAddr:  addr.Bytes(),
		labelChainID:        strconv.FormatUint(chainID, 10),
	}
	b, err := cbor.Marshal(m)
	if err != nil {
		t.Fatalf("encode genesis: %v", err)
	}
	return b
}

// --- fake store ---

type fakeStore struct {
	genesis map[string][]byte
	grants  map[string][]byte
	index   map[string][32]byte
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		genesis: map[string][]byte{},
		grants:  map[string][]byte{},
		index:   map[string][32]byte{},
	}
}

func (s *fakeStore) GetGenesis(_ context.Context, r [32]byte) ([]byte, error) {
	b, ok := s.genesis[hex64(r)]
	if !ok {
		return nil, errStoreMiss
	}
	return b, nil
}

func (s *fakeStore) PutGenesisIfAbsent(_ context.Context, r [32]byte, body []byte) (bool, error) {
	k := hex64(r)
	if _, ok := s.genesis[k]; ok {
		return false, nil
	}
	s.genesis[k] = body
	return true, nil
}

func (s *fakeStore) GetGrant(_ context.Context, r, subject [32]byte) ([]byte, error) {
	b, ok := s.grants[hex64(r)+"/"+hex64(subject)]
	if !ok {
		return nil, errStoreMiss
	}
	return b, nil
}

func (s *fakeStore) PutGrant(_ context.Context, r, subject [32]byte, body []byte) error {
	s.grants[hex64(r)+"/"+hex64(subject)] = body
	return nil
}

func (s *fakeStore) IndexGet(_ context.Context, subject [32]byte) ([32]byte, bool, error) {
	r, ok := s.index[hex64(subject)]
	return r, ok, nil
}

func (s *fakeStore) IndexCreate(_ context.Context, subject, r [32]byte) (bool, [32]byte, error) {
	if existing, ok := s.index[hex64(subject)]; ok {
		return false, existing, nil
	}
	s.index[hex64(subject)] = r
	return true, r, nil
}

func (s *fakeStore) DeleteGenesis(_ context.Context, r [32]byte) error {
	delete(s.genesis, hex64(r))
	return nil
}

func (s *fakeStore) DeleteGrant(_ context.Context, r, subject [32]byte) error {
	delete(s.grants, hex64(r)+"/"+hex64(subject))
	return nil
}

func (s *fakeStore) DeleteIndex(_ context.Context, subject [32]byte) error {
	delete(s.index, hex64(subject))
	return nil
}

func (s *fakeStore) ListForests(_ context.Context) ([][32]byte, error) {
	out := make([][32]byte, 0, len(s.genesis))
	for k := range s.genesis {
		if r, ok := wireLogIDFromHex64(k); ok {
			out = append(out, r)
		}
	}
	return out, nil
}

var errStoreMiss = &storeMissError{}

type storeMissError struct{}

func (*storeMissError) Error() string { return "not found" }

// --- tests ---

func newChainColdAnchored(boot *ecdsa.PrivateKey) *mockChain {
	return &mockChain{
		bootstrapKey:   xyConcat(boot),
		logInitialized: false,
	}
}

func TestVerifyGrantChain_RootAndChild(t *testing.T) {
	logger, _ := NewLogger(0)
	boot := mustKey(t)
	child := mustKey(t)

	var R [32]byte
	R[31] = 1
	var A [32]byte
	A[31] = 2

	chain := newChainColdAnchored(boot)
	store := newFakeStore()
	api := API{Logger: logger, Pool: &mockPool{chain: chain}, Store: store, Bootstrap: NewBootstrapCache()}
	forest := ForestEntry{R: R, ChainID: 84532, Contract: common.HexToAddress("0x1")}

	rootGrant := Grant{LogID: R, OwnerLogID: R, Flags: make([]byte, 8), GrantData: xyConcat(boot)}
	rootTS, err := decodeTransparentStatement(buildGrantStatement(t, boot, rootGrant))
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	if err := api.verifyGrantChain(context.Background(), forest, chain, rootTS); err != nil {
		t.Fatalf("root chain invalid: %v", err)
	}

	childGrant := Grant{LogID: A, OwnerLogID: R, Flags: make([]byte, 8), GrantData: xyConcat(child)}
	childTS, err := decodeTransparentStatement(buildGrantStatement(t, boot, childGrant))
	if err != nil {
		t.Fatalf("decode child: %v", err)
	}
	if err := api.verifyGrantChain(context.Background(), forest, chain, childTS); err != nil {
		t.Fatalf("child chain invalid: %v", err)
	}

	// Child signed by the wrong key (not the owner root) must be rejected.
	bad := buildGrantStatement(t, child, childGrant)
	badTS, err := decodeTransparentStatement(bad)
	if err != nil {
		t.Fatalf("decode bad: %v", err)
	}
	if err := api.verifyGrantChain(context.Background(), forest, chain, badTS); err == nil {
		t.Fatal("expected self-signed child grant to be rejected")
	}

	// Root grantData not matching the bootstrap key must be rejected.
	wrongRoot := Grant{LogID: R, OwnerLogID: R, Flags: make([]byte, 8), GrantData: xyConcat(child)}
	wrongTS, err := decodeTransparentStatement(buildGrantStatement(t, boot, wrongRoot))
	if err != nil {
		t.Fatalf("decode wrong root: %v", err)
	}
	if err := api.verifyGrantChain(context.Background(), forest, chain, wrongTS); err == nil {
		t.Fatal("expected root grantData mismatch to be rejected")
	}
}

func TestResolveAuthority_ColdChild(t *testing.T) {
	logger, _ := NewLogger(0)
	boot := mustKey(t)
	child := mustKey(t)

	var R [32]byte
	R[31] = 1
	var A [32]byte
	A[31] = 2
	addr := common.HexToAddress("0xabc")

	chain := newChainColdAnchored(boot)
	store := newFakeStore()
	store.genesis[hex64(R)] = buildGenesisDoc(t, R, boot, 84532, addr)
	store.index[hex64(A)] = R
	childGrant := Grant{LogID: A, OwnerLogID: R, Flags: make([]byte, 8), GrantData: xyConcat(child)}
	store.grants[hex64(R)+"/"+hex64(A)] = buildGrantStatement(t, boot, childGrant)

	api := API{Logger: logger, Pool: &mockPool{chain: chain}, Store: store, Bootstrap: NewBootstrapCache()}

	// resolveAuthority returns the chain-valid grant-derived key for the cold
	// child; the sealer verifies the delegation certificate locally against it.
	res, err := api.resolveAuthority(context.Background(), A)
	if err != nil {
		t.Fatalf("resolve authority failed: %v", err)
	}
	if res.LogID != A || res.RootLogID != R || res.Source != "grant" {
		t.Fatalf("unexpected result %+v", res)
	}
	if cx, cy := pubXY(child); res.KeyX != cx || res.KeyY != cy {
		t.Fatal("returned key does not match child grantData")
	}

	// An unknown log has no resolvable authority.
	var unknown [32]byte
	unknown[31] = 99
	if _, err := api.resolveAuthority(context.Background(), unknown); err == nil {
		t.Fatal("expected unknown log to fail authority resolution")
	}
}

func TestHandlePostGrantAndAuthorize_HTTP(t *testing.T) {
	logger, _ := NewLogger(0)
	boot := mustKey(t)
	child := mustKey(t)

	var R [32]byte
	R[31] = 1
	var A [32]byte
	A[31] = 2
	addr := common.HexToAddress("0xabc")

	chain := newChainColdAnchored(boot)
	store := newFakeStore()
	store.genesis[hex64(R)] = buildGenesisDoc(t, R, boot, 84532, addr)

	api := API{
		Logger:    logger,
		Pool:      &mockPool{chain: chain},
		Store:     store,
		APIToken:  "secret",
		Bootstrap: NewBootstrapCache(),
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	childGrant := Grant{LogID: A, OwnerLogID: R, Flags: make([]byte, 8), GrantData: xyConcat(child)}
	stmt := buildGrantStatement(t, boot, childGrant)
	reqBody, _ := cbor.Marshal(postGrantRequest{RootLogID: R[:], Statement: stmt})

	post := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/grants", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer secret")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := post(reqBody); rec.Code != http.StatusCreated {
		t.Fatalf("first post want 201 got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := post(reqBody); rec.Code != http.StatusOK {
		t.Fatalf("idempotent post want 200 got %d: %s", rec.Code, rec.Body.String())
	}

	// Missing token -> 401.
	noTok := httptest.NewRequest(http.MethodPost, "/api/grants", bytes.NewReader(reqBody))
	noTokRec := httptest.NewRecorder()
	mux.ServeHTTP(noTokRec, noTok)
	if noTokRec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token want 401 got %d", noTokRec.Code)
	}

	// Cross-forest reuse of A under a different forest R2 -> 409.
	var R2 [32]byte
	R2[31] = 9
	store.genesis[hex64(R2)] = buildGenesisDoc(t, R2, boot, 84532, addr)
	childGrant2 := Grant{LogID: A, OwnerLogID: R2, Flags: make([]byte, 8), GrantData: xyConcat(child)}
	stmt2 := buildGrantStatement(t, boot, childGrant2)
	reqBody2, _ := cbor.Marshal(postGrantRequest{RootLogID: R2[:], Statement: stmt2})
	if rec := post(reqBody2); rec.Code != http.StatusConflict {
		t.Fatalf("cross-forest reuse want 409 got %d: %s", rec.Code, rec.Body.String())
	}

	// Resolve the cold child's authority via the GET endpoint (no token, no
	// certificate): the sealer verifies the delegation locally against this key.
	authReq := httptest.NewRequest(http.MethodGet, "/api/logs/"+hex64(A)+"/authority", nil)
	authRec := httptest.NewRecorder()
	mux.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusOK {
		t.Fatalf("authority want 200 got %d: %s", authRec.Code, authRec.Body.String())
	}
	var resp authorityResponse
	if err := cbor.Unmarshal(authRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode authority resp: %v", err)
	}
	if !bytes.Equal(resp.RootLogID, R[:]) || resp.Source != "grant" {
		t.Fatalf("unexpected authority resp %+v", resp)
	}
	if cx, cy := pubXY(child); !bytes.Equal(resp.X, cx[:]) || !bytes.Equal(resp.Y, cy[:]) {
		t.Fatal("authority key does not match child grantData")
	}

	// An unregistered log has no resolvable authority -> 503.
	var unknown [32]byte
	unknown[31] = 77
	unkReq := httptest.NewRequest(http.MethodGet, "/api/logs/"+hex64(unknown)+"/authority", nil)
	unkRec := httptest.NewRecorder()
	mux.ServeHTTP(unkRec, unkReq)
	if unkRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unknown authority want 503 got %d", unkRec.Code)
	}
}
