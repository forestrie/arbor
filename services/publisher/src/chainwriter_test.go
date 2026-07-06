package publisher

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// anvilKey0 is the well-known anvil dev private key (address
// 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266). Test-only.
const anvilKey0 = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

func newTestWriter(t *testing.T) *ChainWriter {
	t.Helper()
	w, err := NewChainWriter(map[uint64]string{31337: "http://127.0.0.1:8545"}, anvilKey0, WriteConfig{})
	if err != nil {
		t.Fatalf("NewChainWriter: %v", err)
	}
	return w
}

func TestRevertRetryable(t *testing.T) {
	transient := []string{
		"SizeMustIncrease",
		"SizeMustIncrease(3, 5)",
		"InvalidConsistencyProof",
		"MinGrowthNotMet(1, 1, 2)",
	}
	for _, r := range transient {
		if !revertRetryable(r) {
			t.Errorf("%q should be retryable", r)
		}
	}
	terminal := []string{
		"GrantRequirement(1, 2)",
		"ConsistencyReceiptSignatureInvalid",
		"InvalidCheckpointCose",
		"LogNotFound(0x00)",
		"", // unknown/empty -> terminal
		"SomeUnknownError",
	}
	for _, r := range terminal {
		if revertRetryable(r) {
			t.Errorf("%q should be terminal (not retryable)", r)
		}
	}
}

// fakeDataError implements the go-ethereum rpc.DataError shape so classifyRevert
// can be exercised without a live node.
type fakeDataError struct{ data string }

func (e *fakeDataError) Error() string          { return "execution reverted" }
func (e *fakeDataError) ErrorData() interface{} { return e.data }

func TestClassifyRevertGrantRequirement(t *testing.T) {
	w := newTestWriter(t)

	errABI, err := abi.JSON(strings.NewReader(univocityErrorsABI))
	if err != nil {
		t.Fatalf("parse errors abi: %v", err)
	}
	ge := errABI.Errors["GrantRequirement"]
	args, err := ge.Inputs.Pack(big.NewInt(1), big.NewInt(2))
	if err != nil {
		t.Fatalf("pack args: %v", err)
	}
	data := append(append([]byte{}, ge.ID.Bytes()[:4]...), args...)
	fake := &fakeDataError{data: "0x" + hex.EncodeToString(data)}

	reason, ok := w.classifyRevert(fake)
	if !ok {
		t.Fatalf("expected classification, got none")
	}
	if !strings.Contains(reason, "GrantRequirement") {
		t.Errorf("reason = %q, want it to contain GrantRequirement", reason)
	}
}

func TestClassifyRevertUnknownSelector(t *testing.T) {
	w := newTestWriter(t)
	// A selector not in the table must not classify.
	fake := &fakeDataError{data: "0xdeadbeef"}
	if _, ok := w.classifyRevert(fake); ok {
		t.Errorf("unexpected classification for unknown selector")
	}
	// A non-data error must not classify.
	if _, ok := w.classifyRevert(errPlain("boom")); ok {
		t.Errorf("unexpected classification for plain error")
	}
}

type errPlain string

func (e errPlain) Error() string { return string(e) }

func TestParsePublisherKey(t *testing.T) {
	if _, err := parsePublisherKey(anvilKey0); err != nil {
		t.Errorf("valid key rejected: %v", err)
	}
	if _, err := parsePublisherKey("0x" + anvilKey0); err != nil {
		t.Errorf("0x-prefixed key rejected: %v", err)
	}
	if _, err := parsePublisherKey("not-hex"); err == nil {
		t.Errorf("expected error for invalid key")
	}
}
