package univocity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/forestrie/arbor/services/pkgs/logid"
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

func protectedKS256(t *testing.T) []byte {
	t.Helper()
	b, err := cbor.Marshal(map[int]interface{}{1: coseAlgKS256})
	if err != nil {
		t.Fatalf("encode protected: %v", err)
	}
	return b
}

func mustKS256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: %v", err)
	}
	return k
}

func ks256AddressFromKey(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	return crypto.PubkeyToAddress(priv.PublicKey).Bytes()
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

func signSign1KS256(t *testing.T, priv *ecdsa.PrivateKey, protected, payloadDigest []byte) []byte {
	t.Helper()
	sig := []interface{}{"Signature1", protected, []byte{}, payloadDigest}
	sb, err := cbor.Marshal(sig)
	if err != nil {
		t.Fatalf("encode sig structure: %v", err)
	}
	hash := crypto.Keccak256(sb)
	out, err := crypto.Sign(hash, priv)
	if err != nil {
		t.Fatalf("sign KS256: %v", err)
	}
	return out
}

func buildGrantStatement(t *testing.T, ownerPriv *ecdsa.PrivateKey, g Grant) []byte {
	t.Helper()
	logWire := g.LogID.ToPaddedWire32()
	ownerWire := g.OwnerLogID.ToPaddedWire32()
	inner := map[int]interface{}{
		grantKeyLogID:      logWire[:],
		grantKeyOwnerLogID: ownerWire[:],
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

func buildGrantStatementKS256(t *testing.T, ownerPriv *ecdsa.PrivateKey, g Grant) []byte {
	t.Helper()
	logWire := g.LogID.ToPaddedWire32()
	ownerWire := g.OwnerLogID.ToPaddedWire32()
	inner := map[int]interface{}{
		grantKeyLogID:      logWire[:],
		grantKeyOwnerLogID: ownerWire[:],
		grantKeyFlags:      g.Flags,
		grantKeyMaxHeight:  g.MaxHeight,
		grantKeyMinGrowth:  g.MinGrowth,
		grantKeyGrantData:  g.GrantData,
	}
	embedded, err := cbor.Marshal(inner)
	if err != nil {
		t.Fatalf("encode grant: %v", err)
	}
	protected := protectedKS256(t)
	digest := sha256.Sum256(embedded)
	sig := signSign1KS256(t, ownerPriv, protected, digest[:])
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

func buildGenesisDoc(t *testing.T, r logid.UUID, boot *ecdsa.PrivateKey, chainID uint64, addr common.Address) []byte {
	t.Helper()
	x, y := pubXY(boot)
	m := map[int]interface{}{
		coseKeyKty:          coseKtyEc2,
		coseKeyAlg:          coseAlgES256,
		coseEc2Crv:          coseCrvP256,
		coseEc2X:            x[:],
		coseEc2Y:            y[:],
		labelGenesisVersion: genesisSchemaV1,
		labelBootstrapLogID: func() []byte { w := r.ToPaddedWire32(); return w[:] }(),
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
	index   map[string]logid.UUID
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		genesis: map[string][]byte{},
		grants:  map[string][]byte{},
		index:   map[string]logid.UUID{},
	}
}

func (s *fakeStore) grantStoreKey(r, subject logid.UUID, class GrantClass) string {
	return r.String() + "/" + grantClassDir(class) + "/" + subject.String()
}

func (s *fakeStore) GetGenesis(_ context.Context, r logid.UUID) ([]byte, error) {
	b, ok := s.genesis[r.String()]
	if !ok {
		return nil, errStoreMiss
	}
	return b, nil
}

func (s *fakeStore) PutGenesisIfAbsent(_ context.Context, r logid.UUID, body []byte) (bool, error) {
	k := r.String()
	if _, ok := s.genesis[k]; ok {
		return false, nil
	}
	s.genesis[k] = body
	return true, nil
}

func (s *fakeStore) GetGrant(_ context.Context, r, subject logid.UUID) ([]byte, error) {
	for _, class := range []GrantClass{GrantClassAuthLog, GrantClassDataLog} {
		if b, ok := s.grants[s.grantStoreKey(r, subject, class)]; ok {
			return b, nil
		}
	}
	return nil, errStoreMiss
}

func (s *fakeStore) PutGrant(_ context.Context, r, subject logid.UUID, class GrantClass, body []byte) error {
	s.grants[s.grantStoreKey(r, subject, class)] = body
	return nil
}

func (s *fakeStore) IndexGet(_ context.Context, subject logid.UUID) (logid.UUID, bool, error) {
	r, ok := s.index[subject.String()]
	return r, ok, nil
}

func (s *fakeStore) IndexCreate(_ context.Context, subject, r logid.UUID) (bool, logid.UUID, error) {
	if existing, ok := s.index[subject.String()]; ok {
		return false, existing, nil
	}
	s.index[subject.String()] = r
	return true, r, nil
}

func (s *fakeStore) DeleteGenesis(_ context.Context, r logid.UUID) error {
	delete(s.genesis, r.String())
	return nil
}

func (s *fakeStore) DeleteGrant(_ context.Context, r, subject logid.UUID) error {
	for _, class := range []GrantClass{GrantClassAuthLog, GrantClassDataLog} {
		delete(s.grants, s.grantStoreKey(r, subject, class))
	}
	return nil
}

func (s *fakeStore) DeleteIndex(_ context.Context, subject logid.UUID) error {
	delete(s.index, subject.String())
	return nil
}

func (s *fakeStore) ListForests(_ context.Context) ([]logid.UUID, error) {
	out := make([]logid.UUID, 0, len(s.genesis))
	for k := range s.genesis {
		id, err := logid.ParseUUIDString(k)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}

var errStoreMiss = &storeMissError{}

type storeMissError struct{}

func (*storeMissError) Error() string { return "not found" }

// --- tests ---

func newChainColdAnchored(boot *ecdsa.PrivateKey) *mockChain {
	return &mockChain{
		bootstrapAlg:   coseAlgES256,
		bootstrapKey:   xyConcat(boot),
		logInitialized: false,
	}
}

func newChainColdAnchoredKS256(boot *ecdsa.PrivateKey) *mockChain {
	return &mockChain{
		bootstrapAlg:   coseAlgKS256,
		bootstrapKey:   crypto.PubkeyToAddress(boot.PublicKey).Bytes(),
		logInitialized: false,
	}
}

func TestVerifyGrantChain_RootAndChild(t *testing.T) {
	logger, _ := NewLogger(0)
	boot := mustKey(t)
	child := mustKey(t)

	R := testLogID(1)
	A := testLogID(2)

	chain := newChainColdAnchored(boot)
	store := newFakeStore()
	api := API{Logger: logger, Pool: &mockPool{chain: chain}, Store: store, Bootstrap: NewBootstrapCache()}
	forest := ForestEntry{R: R, ChainID: 84532, Contract: common.HexToAddress("0x1")}

	rootGrant := Grant{LogID: R, OwnerLogID: R, Flags: authLogFlags(), GrantData: xyConcat(boot)}
	rootTS, err := decodeTransparentStatement(buildGrantStatement(t, boot, rootGrant))
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	if err := api.verifyGrantChain(context.Background(), forest, chain, rootTS); err != nil {
		t.Fatalf("root chain invalid: %v", err)
	}

	childGrant := Grant{LogID: A, OwnerLogID: R, Flags: authLogFlags(), GrantData: xyConcat(child)}
	childTS, err := decodeTransparentStatement(buildGrantStatement(t, boot, childGrant))
	if err != nil {
		t.Fatalf("decode child: %v", err)
	}
	if err := api.verifyGrantChain(context.Background(), forest, chain, childTS); err != nil {
		t.Fatalf("child chain invalid: %v", err)
	}

	bad := buildGrantStatement(t, child, childGrant)
	badTS, err := decodeTransparentStatement(bad)
	if err != nil {
		t.Fatalf("decode bad: %v", err)
	}
	if err := api.verifyGrantChain(context.Background(), forest, chain, badTS); err == nil {
		t.Fatal("expected self-signed child grant to be rejected")
	}

	wrongRoot := Grant{LogID: R, OwnerLogID: R, Flags: authLogFlags(), GrantData: xyConcat(child)}
	wrongTS, err := decodeTransparentStatement(buildGrantStatement(t, boot, wrongRoot))
	if err != nil {
		t.Fatalf("decode wrong root: %v", err)
	}
	if err := api.verifyGrantChain(context.Background(), forest, chain, wrongTS); err == nil {
		t.Fatal("expected root grantData mismatch to be rejected")
	}
}

func TestVerifyGrantChain_KS256Root(t *testing.T) {
	logger, _ := NewLogger(0)
	boot := mustKS256Key(t)
	child := mustKey(t)

	R := testLogID(10)
	A := testLogID(11)
	bootAddr := ks256AddressFromKey(t, boot)

	chain := newChainColdAnchoredKS256(boot)
	store := newFakeStore()
	api := API{Logger: logger, Pool: &mockPool{chain: chain}, Store: store, Bootstrap: NewBootstrapCache()}
	forest := ForestEntry{R: R, ChainID: 84532, Contract: common.HexToAddress("0x1")}

	rootGrant := Grant{LogID: R, OwnerLogID: R, Flags: authLogFlags(), GrantData: bootAddr}
	rootTS, err := decodeTransparentStatement(buildGrantStatementKS256(t, boot, rootGrant))
	if err != nil {
		t.Fatalf("decode KS256 root: %v", err)
	}
	if err := api.verifyGrantChain(context.Background(), forest, chain, rootTS); err != nil {
		t.Fatalf("KS256 root chain invalid: %v", err)
	}

	childGrant := Grant{LogID: A, OwnerLogID: R, Flags: authLogFlags(), GrantData: xyConcat(child)}
	childTS, err := decodeTransparentStatement(buildGrantStatementKS256(t, boot, childGrant))
	if err != nil {
		t.Fatalf("decode KS256 child: %v", err)
	}
	if err := api.verifyGrantChain(context.Background(), forest, chain, childTS); err != nil {
		t.Fatalf("KS256 child chain invalid: %v", err)
	}

	bad := buildGrantStatementKS256(t, child, childGrant)
	badTS, err := decodeTransparentStatement(bad)
	if err != nil {
		t.Fatalf("decode bad KS256 child: %v", err)
	}
	if err := api.verifyGrantChain(context.Background(), forest, chain, badTS); err == nil {
		t.Fatal("expected self-signed KS256 child grant to be rejected")
	}
}

func TestResolveAuthority_ColdChild(t *testing.T) {
	logger, _ := NewLogger(0)
	boot := mustKey(t)
	child := mustKey(t)

	R := testLogID(1)
	A := testLogID(2)
	addr := common.HexToAddress("0xabc")

	chain := newChainColdAnchored(boot)
	store := newFakeStore()
	store.genesis[R.String()] = buildGenesisDoc(t, R, boot, 84532, addr)
	store.index[A.String()] = R
	childGrant := Grant{LogID: A, OwnerLogID: R, Flags: authLogFlags(), GrantData: xyConcat(child)}
	store.grants[store.grantStoreKey(R, A, GrantClassAuthLog)] = buildGrantStatement(t, boot, childGrant)

	api := API{Logger: logger, Pool: &mockPool{chain: chain}, Store: store, Bootstrap: NewBootstrapCache()}

	res, err := api.resolveAuthority(context.Background(), A)
	if err != nil {
		t.Fatalf("resolve authority failed: %v", err)
	}
	if res.LogID != A || res.RootLogID != R || res.Source != "grant" {
		t.Fatalf("unexpected result %+v", res)
	}
	if !bytes.Equal(res.Key, xyConcat(child)) {
		t.Fatal("returned key does not match child grantData")
	}

	unknown := testLogID(99)
	if _, err := api.resolveAuthority(context.Background(), unknown); err == nil {
		t.Fatal("expected unknown log to fail authority resolution")
	}
}

// mockChainEmptyResponse simulates eth_call to an undeployed contract address.
type mockChainEmptyResponse struct{}

func (mockChainEmptyResponse) RootLogId(context.Context) (logid.UUID, error) {
	return logid.Zero, errors.New("empty contract response")
}

func (mockChainEmptyResponse) BootstrapConfig(context.Context) (int64, []byte, error) {
	return 0, nil, errors.New("abi: attempting to unmarshal an empty string while arguments are expected")
}

func (mockChainEmptyResponse) IsLogInitialized(context.Context, logid.UUID) (bool, error) {
	return false, errors.New("abi: attempting to unmarshal an empty string while arguments are expected")
}

func (mockChainEmptyResponse) LogConfig(context.Context, logid.UUID) (LogConfig, error) {
	return LogConfig{}, errors.New("empty contract response")
}

func (mockChainEmptyResponse) LogRootKey(context.Context, logid.UUID) ([32]byte, [32]byte, error) {
	return [32]byte{}, [32]byte{}, errors.New("empty contract response")
}

func (mockChainEmptyResponse) HasCode(context.Context, common.Address) (bool, error) {
	return false, nil
}

func (mockChainEmptyResponse) IsValidSignature(ctx context.Context, addr common.Address, hash, sig []byte) error {
	_ = ctx
	_ = addr
	_ = hash
	_ = sig
	return errERC1271Failed
}

func TestResolveAuthority_UnanchoredColdChild(t *testing.T) {
	logger, _ := NewLogger(0)
	boot := mustKey(t)
	child := mustKey(t)

	R := testLogID(1)
	A := testLogID(2)
	addr := common.HexToAddress("0xabc")

	store := newFakeStore()
	store.genesis[R.String()] = buildGenesisDoc(t, R, boot, 84532, addr)
	store.index[A.String()] = R
	childGrant := Grant{LogID: A, OwnerLogID: R, Flags: authLogFlags(), GrantData: xyConcat(child)}
	store.grants[store.grantStoreKey(R, A, GrantClassAuthLog)] = buildGrantStatement(t, boot, childGrant)

	api := API{
		Logger:                 logger,
		Pool:                   &mockPool{chain: mockChainEmptyResponse{}},
		Store:                  store,
		Bootstrap:              NewBootstrapCache(),
		AllowUnanchoredGenesis: true,
	}

	res, err := api.resolveAuthority(context.Background(), A)
	if err != nil {
		t.Fatalf("resolve authority failed: %v", err)
	}
	if res.LogID != A || res.RootLogID != R || res.Source != "grant" {
		t.Fatalf("unexpected result %+v", res)
	}
	if !bytes.Equal(res.Key, xyConcat(child)) {
		t.Fatal("returned key does not match child grantData")
	}
}

func TestHandlePostGrantAndAuthorize_HTTP(t *testing.T) {
	logger, _ := NewLogger(0)
	boot := mustKey(t)
	child := mustKey(t)

	R := testLogID(1)
	A := testLogID(2)
	addr := common.HexToAddress("0xabc")

	chain := newChainColdAnchored(boot)
	store := newFakeStore()
	store.genesis[R.String()] = buildGenesisDoc(t, R, boot, 84532, addr)

	api := API{
		Logger:    logger,
		Pool:      &mockPool{chain: chain},
		Store:     store,
		APIToken:  "secret",
		Bootstrap: NewBootstrapCache(),
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	childGrant := Grant{LogID: A, OwnerLogID: R, Flags: authLogFlags(), GrantData: xyConcat(child)}
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

	noTok := httptest.NewRequest(http.MethodPost, "/api/grants", bytes.NewReader(reqBody))
	noTokRec := httptest.NewRecorder()
	mux.ServeHTTP(noTokRec, noTok)
	if noTokRec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token want 401 got %d", noTokRec.Code)
	}

	R2 := testLogID(9)
	store.genesis[R2.String()] = buildGenesisDoc(t, R2, boot, 84532, addr)
	childGrant2 := Grant{LogID: A, OwnerLogID: R2, Flags: authLogFlags(), GrantData: xyConcat(child)}
	stmt2 := buildGrantStatement(t, boot, childGrant2)
	reqBody2, _ := cbor.Marshal(postGrantRequest{RootLogID: R2[:], Statement: stmt2})
	if rec := post(reqBody2); rec.Code != http.StatusConflict {
		t.Fatalf("cross-forest reuse want 409 got %d: %s", rec.Code, rec.Body.String())
	}

	authReq := httptest.NewRequest(http.MethodGet, "/api/logs/"+A.String()+"/authority", nil)
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
	if !bytes.Equal(resp.Key, xyConcat(child)) {
		t.Fatal("authority key does not match child grantData")
	}

	unknown := testLogID(77)
	unkReq := httptest.NewRequest(http.MethodGet, "/api/logs/"+unknown.String()+"/authority", nil)
	unkRec := httptest.NewRecorder()
	mux.ServeHTTP(unkRec, unkReq)
	if unkRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unknown authority want 503 got %d", unkRec.Code)
	}
}
