package univocity

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// Raw eth_call return bytes captured live from an ImutableUnivocity v0.1.7
// deployment on Base Sepolia (contract 0x9721…c57D, an initialized ES256 log):
// a single tuple return (`LogConfig memory`) — 0x20 tuple head offset, then
// kind=1, authLogId, rootKey offset, initializedAt, then the dynamic 64-byte
// rootKey (P-256 x||y). The pre-FOR-389 flat-output ABI mis-decoded exactly
// these bytes ("abi: cannot marshal in to go slice: offset … over slice
// boundary"), 502ing every post-anchor authority lookup.
const logConfigReturnFixtureHex = "" +
	"0000000000000000000000000000000000000000000000000000000000000020" +
	"0000000000000000000000000000000000000000000000000000000000000001" +
	"000000000000000000000000000000009721648961419f4535963f4da7858c36" +
	"0000000000000000000000000000000000000000000000000000000000000080" +
	"0000000000000000000000000000000000000000000000000000000002a0579c" +
	"0000000000000000000000000000000000000000000000000000000000000040" +
	"a92f7793422635ffdcedbd731f7fd4404c8f38eb8d53e0e4cce2bb44b76063e4" +
	"a8ae29ac8e72bf746a65dc16f507a59c7adc01c09ecbbe2d04f4fc80d4f64422"

// TestLogConfigTupleDecode pins the FOR-389 fix: the univocityViewABI must
// declare logConfig's return as a tuple, and the decode path must unwrap it
// into LogConfig correctly, against real on-chain return bytes.
func TestLogConfigTupleDecode(t *testing.T) {
	out, err := hex.DecodeString(logConfigReturnFixtureHex)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	parsed, err := abi.JSON(strings.NewReader(univocityViewABI))
	if err != nil {
		t.Fatalf("parse ABI: %v", err)
	}

	vals, err := parsed.Unpack("logConfig", out)
	if err != nil {
		t.Fatalf("unpack (flat-output regression — FOR-389): %v", err)
	}
	if len(vals) != 1 {
		t.Fatalf("expected single tuple return, got %d values", len(vals))
	}
	tup := abi.ConvertType(vals[0], new(logConfigTuple)).(*logConfigTuple)

	if tup.Kind != 1 {
		t.Errorf("kind = %d, want 1", tup.Kind)
	}
	wantAuth := "000000000000000000000000000000009721648961419f4535963f4da7858c36"
	if hex.EncodeToString(tup.AuthLogId[:]) != wantAuth {
		t.Errorf("authLogId = %x", tup.AuthLogId)
	}
	if len(tup.RootKey) != 64 {
		t.Errorf("rootKey length = %d, want 64 (P-256 x||y)", len(tup.RootKey))
	}
	if !tup.InitializedAt.IsUint64() || tup.InitializedAt.Uint64() != 0x2a0579c {
		t.Errorf("initializedAt = %v, want %d", tup.InitializedAt, 0x2a0579c)
	}
}
