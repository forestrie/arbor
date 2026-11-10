package univocity

import (
	"bytes"
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/fxamacker/cbor/v2"
)

// buildGenesisDocV2 builds the version 2 genesis document canopy posts, for
// an ES256 bootstrap key.
func buildGenesisDocV2(t *testing.T, r logid.UUID, boot *ecdsa.PrivateKey, chainID uint64, addr common.Address) []byte {
	t.Helper()
	wire := r.ToPaddedWire32()
	b, err := cbor.Marshal(map[int]interface{}{
		labelGenesisVersion: genesisSchemaV2,
		labelBootstrapAlg:   coseAlgES256,
		labelBootstrapKey:   xyConcat(boot),
		labelBootstrapLogID: wire[:],
		labelUnivocityAddr:  addr.Bytes(),
		labelChainID:        strconv.FormatUint(chainID, 10),
	})
	if err != nil {
		t.Fatalf("encode genesis: %v", err)
	}
	return b
}

// postGenesis posts a genesis for forest root R2 on the fixture's contract,
// keyed by the contract's bootstrap key.
func (f *claimFixture) postGenesis(R2 logid.UUID) *httptest.ResponseRecorder {
	f.t.Helper()
	body := buildGenesisDocV2(f.t, R2, f.boot, 84532, common.HexToAddress("0xabc"))
	req := httptest.NewRequest(http.MethodPost, "/api/forest/"+R2.String()+"/genesis",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

// A contract takes one root (platform rule P14): a genesis binding a forest
// to a contract that another log already roots is refused before anything
// is stored. 422, not 409, which canopy reads as "genesis exists".
func TestPostGenesis_ContractRootedAtAnotherLogRefused(t *testing.T) {
	f := newClaimFixture(t)
	f.chain.rootLogId = f.R
	R2 := testLogID(40)

	wantStatus(t, f.postGenesis(R2), http.StatusUnprocessableEntity, "genesis on a rooted contract")
	if _, ok := f.store.genesis[R2.String()]; ok {
		t.Fatal("a refused genesis must store no genesis")
	}
	if _, ok := f.store.index[R2.String()]; ok {
		t.Fatal("a refused genesis must claim no index entry")
	}
}

// A contract whose recorded root is this forest's own root accepts the
// genesis: it is the forest the contract was bootstrapped for.
func TestPostGenesis_ContractRootedAtThisForestAccepted(t *testing.T) {
	f := newClaimFixture(t)
	R2 := testLogID(41)
	f.chain.rootLogId = R2

	wantStatus(t, f.postGenesis(R2), http.StatusCreated, "genesis on its own contract")
}
