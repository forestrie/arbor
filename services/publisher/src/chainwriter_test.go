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

func TestRevertLabel(t *testing.T) {
	// Known IUnivocity error names pass through; everything else is bucketed.
	for _, name := range []string{"GrantRequirement", "SizeMustIncrease", "ConsistencyReceiptSignatureInvalid"} {
		if got := RevertLabel(name); got != name {
			t.Errorf("RevertLabel(%q) = %q, want passthrough", name, got)
		}
	}
	for _, raw := range []string{"", "execution reverted: 0xdeadbeef", "Peak count mismatch", "SomeFutureError"} {
		if got := RevertLabel(raw); got != "unrecognized" {
			t.Errorf("RevertLabel(%q) = %q, want unrecognized", raw, got)
		}
	}
}

func TestRevertLabelInconsistentReceiptSignature(t *testing.T) {
	// Delegation and cosecbor error names must be bounded metric labels, not
	// "unrecognized" (plan-2607-10 Track C: the live lane-A revert was opaque).
	for _, name := range []string{
		"InconsistentReceiptSignature",
		"DelegationUnsupportedForAlg",
		"MissingCheckpointSignerKey",
		"SignatureVerificationFailed",
		"InvalidCoseCborStructure",
	} {
		if got := RevertLabel(name); got != name {
			t.Errorf("RevertLabel(%q) = %q, want passthrough", name, got)
		}
	}
}

func TestClassifyRevertInconsistentReceiptSignature(t *testing.T) {
	w := newTestWriter(t)

	errABI, err := abi.JSON(strings.NewReader(univocityErrorsABI))
	if err != nil {
		t.Fatalf("parse errors abi: %v", err)
	}
	irs, ok := errABI.Errors["InconsistentReceiptSignature"]
	if !ok {
		t.Fatal("InconsistentReceiptSignature missing from univocityErrorsABI")
	}
	// Selector confirmed against the live lane-A revert (0x7331c077).
	if got := hex.EncodeToString(irs.ID.Bytes()[:4]); got != "7331c077" {
		t.Fatalf("selector = %s, want 7331c077", got)
	}
	// ALG_ES256 (-7) receipt on an ALG_KS256 (-65799) root log.
	args, err := irs.Inputs.Pack(int64(-7), int64(-65799))
	if err != nil {
		t.Fatalf("pack args: %v", err)
	}
	data := append(append([]byte{}, irs.ID.Bytes()[:4]...), args...)
	fake := &fakeDataError{data: "0x" + hex.EncodeToString(data)}

	reason, ok := w.classifyRevert(fake)
	if !ok {
		t.Fatal("expected classification, got none")
	}
	if reason != "InconsistentReceiptSignature" {
		t.Errorf("reason = %q, want InconsistentReceiptSignature", reason)
	}
	if got := RevertLabel(reason); got != "InconsistentReceiptSignature" {
		t.Errorf("RevertLabel(%q) = %q, want passthrough", reason, got)
	}
}

// pinnedErrorSelectors pins every fragment in univocityErrorsABI to its
// keccak selector so a transcription typo cannot silently degrade
// classification to "unrecognized" (plan-0050 L4).
var pinnedErrorSelectors = map[string]string{
	"AlreadyInitialized":                   "0dc149f0",
	"CheckpointCountExceeded":              "10de10f5",
	"CheckpointIndexOutOfDelegationRange":  "73ac1b39",
	"ClaimNotFound":                        "1f01cfba",
	"ConsistencyReceiptSignatureInvalid":   "7fdcc119",
	"DelegationLogIdMismatch":              "60fc9497",
	"DelegationSignatureInvalid":           "7cbfed2d",
	"DelegationUnsupportedForAlg":          "bf325094",
	"DuplicateRootKeyInDelegation":         "65193881",
	"FirstCheckpointSizeTooSmall":          "dbb8b60c",
	"GrantDataMustMatchBootstrap":          "729e6a6f",
	"GrantRequirement":                     "3c02cf56",
	"InconsistentReceiptSignature":         "7331c077",
	"InvalidAccumulatorLength":             "6454496d",
	"InvalidCheckpointCose":                "fb80f567",
	"InvalidConsistencyProof":              "4af9512c",
	"InvalidCoseCborStructure":             "2e5a4f93",
	"InvalidDelegationKeyLength":           "37fcf219",
	"InvalidDelegationSignatureLength":     "05bcc30d",
	"InvalidPaymentReceipt":                "f2d20499",
	"InvalidReceiptInclusionProof":         "4f5bf2d4",
	"InvalidRecoveryId":                    "6d6cb2c3",
	"InvalidRootKeyLength":                 "2903bfbd",
	"InvalidSignatureChain":                "7f833592",
	"InvalidSignatureLength":               "d615d706",
	"LogNotFound":                          "3dd8822c",
	"LogRootKeyNotSet":                     "c4a5db65",
	"MaxHeightExceeded":                    "188aa6ed",
	"MinGrowthNotMet":                      "67603ff8",
	"MissingCheckpointSignerKey":           "2603bf2f",
	"MissingDelegationCert":                "7e968d05",
	"MissingRootKeyForRecovery":            "fcf3d0de",
	"NotInitialized":                       "87138d5c",
	"ProofPayloadExceedsMaxHeight":         "d91da2f6",
	"ReceiptLogIdMismatch":                 "8dcc5aad",
	"RecoveredKeyMismatchIncludedKey":      "b8d58012",
	"RecoveryIdDuplicate":                  "b7da94e2",
	"SignatureVerificationFailed":          "729d0f6b",
	"SizeMustIncrease":                     "426d6a07",
	"UnexpectedMajorType":                  "cc7fe4cf",
	"UnsupportedAlgorithm":                 "bd3b5c83",
}

func TestUnivocityErrorsABISelectorsPinned(t *testing.T) {
	errABI, err := abi.JSON(strings.NewReader(univocityErrorsABI))
	if err != nil {
		t.Fatalf("parse errors abi: %v", err)
	}
	if len(errABI.Errors) != len(pinnedErrorSelectors) {
		t.Fatalf("ABI has %d errors, pin table has %d — update pinnedErrorSelectors",
			len(errABI.Errors), len(pinnedErrorSelectors))
	}
	for name, want := range pinnedErrorSelectors {
		e, ok := errABI.Errors[name]
		if !ok {
			t.Errorf("pinned error %q missing from univocityErrorsABI", name)
			continue
		}
		got := hex.EncodeToString(e.ID.Bytes()[:4])
		if got != want {
			t.Errorf("%s selector = %s, want %s (transcription typo?)", name, got, want)
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

// TestFinalizeResultDisposition locks the daemon disposition mapping after the
// binary revert model (adr-0008): a mined revert (OutcomeReverted) is terminal
// ack (StatusReverted), only a never-mined tx (OutcomeUnsubmitted) retries.
func TestFinalizeResultDisposition(t *testing.T) {
	cases := []struct {
		outcome SubmitOutcome
		want    PublishStatus
		ack     bool
	}{
		{OutcomePublished, StatusPublished, true},
		{OutcomeSuperseded, StatusAlreadyAnchored, true},
		{OutcomeReverted, StatusReverted, true},
		{OutcomeUnsubmitted, StatusRetry, false},
	}
	for _, c := range cases {
		got := FinalizeResult(PublishResult{}, SubmitResult{Outcome: c.outcome})
		if got.Status != c.want || got.ShouldAck() != c.ack {
			t.Errorf("outcome %v -> status=%v ack=%v, want status=%v ack=%v",
				c.outcome, got.Status, got.ShouldAck(), c.want, c.ack)
		}
	}
}
