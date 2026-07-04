package publishproof

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// ConsistencyProof mirrors the univocity ConsistencyProof calldata tuple (MMR
// profile, pre-decoded; no CBOR on-chain). One element per sealed step when
// chaining a publisher catch-up (FOR-314).
type ConsistencyProof struct {
	TreeSize1  uint64
	TreeSize2  uint64
	Paths      [][][32]byte
	RightPeaks [][32]byte
}

// DelegationProof mirrors the univocity DelegationProof calldata tuple
// (ADR-0006). Zero value means no delegation.
type DelegationProof struct {
	ProtectedHeader []byte
	DelegationKey   []byte
	MmrStart        uint64
	MmrEnd          uint64
	Signature       []byte
}

// ConsistencyReceipt mirrors the univocity ConsistencyReceipt calldata tuple:
// the pre-decoded parts of the sealer's COSE Sign1 checkpoint plus the proof
// chain the contract verifies it against.
type ConsistencyReceipt struct {
	ProtectedHeader   []byte
	Signature         []byte
	ConsistencyProofs []ConsistencyProof
	DelegationProof   DelegationProof
}

// InclusionProof mirrors the univocity InclusionProof calldata tuple (grant
// inclusion in the owner log).
type InclusionProof struct {
	Index uint64
	Path  [][32]byte
}

// publishABI carries the publishCheckpoint and logState fragments of the
// IUnivocity ABI. Component names must match types.sol so go-ethereum can map
// them onto the Go structs.
const publishABI = `[
	{"type":"function","name":"publishCheckpoint","stateMutability":"nonpayable","inputs":[
		{"name":"consistencyParts","type":"tuple","components":[
			{"name":"protectedHeader","type":"bytes"},
			{"name":"signature","type":"bytes"},
			{"name":"consistencyProofs","type":"tuple[]","components":[
				{"name":"treeSize1","type":"uint64"},
				{"name":"treeSize2","type":"uint64"},
				{"name":"paths","type":"bytes32[][]"},
				{"name":"rightPeaks","type":"bytes32[]"}
			]},
			{"name":"delegationProof","type":"tuple","components":[
				{"name":"protectedHeader","type":"bytes"},
				{"name":"delegationKey","type":"bytes"},
				{"name":"mmrStart","type":"uint64"},
				{"name":"mmrEnd","type":"uint64"},
				{"name":"signature","type":"bytes"}
			]}
		]},
		{"name":"grantInclusionProof","type":"tuple","components":[
			{"name":"index","type":"uint64"},
			{"name":"path","type":"bytes32[]"}
		]},
		{"name":"grantIDTimestampBe","type":"bytes8"},
		{"name":"publishGrant","type":"tuple","components":[
			{"name":"logId","type":"bytes32"},
			{"name":"grant","type":"uint256"},
			{"name":"request","type":"uint256"},
			{"name":"maxHeight","type":"uint64"},
			{"name":"minGrowth","type":"uint64"},
			{"name":"ownerLogId","type":"bytes32"},
			{"name":"grantData","type":"bytes"}
		]}
	],"outputs":[]},
	{"type":"function","name":"logState","stateMutability":"view","inputs":[
		{"name":"logId","type":"bytes32"}
	],"outputs":[
		{"name":"","type":"tuple","components":[
			{"name":"accumulator","type":"bytes32[]"},
			{"name":"size","type":"uint64"}
		]}
	]}
]`

var univocityABI = mustParseABI(publishABI)

func mustParseABI(raw string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(raw))
	if err != nil {
		panic(fmt.Sprintf("publishproof: invalid embedded ABI: %v", err))
	}
	return parsed
}

// EncodePublishCheckpoint returns the publishCheckpoint calldata (selector +
// ABI-encoded arguments) for a permissionless checkpoint submission.
func EncodePublishCheckpoint(
	receipt ConsistencyReceipt,
	grantInclusionProof InclusionProof,
	grantIDTimestampBe [8]byte,
	publishGrant PublishGrant,
) ([]byte, error) {
	return univocityABI.Pack(
		"publishCheckpoint",
		receipt,
		grantInclusionProof,
		grantIDTimestampBe,
		publishGrant,
	)
}

// DecodePublishCheckpoint unpacks publishCheckpoint calldata produced by
// EncodePublishCheckpoint (or any ABI-compatible encoder).
func DecodePublishCheckpoint(calldata []byte) (
	ConsistencyReceipt, InclusionProof, [8]byte, PublishGrant, error,
) {
	var (
		receipt     ConsistencyReceipt
		inclusion   InclusionProof
		idTimestamp [8]byte
		grant       PublishGrant
	)
	method := univocityABI.Methods["publishCheckpoint"]
	if len(calldata) < 4 || string(calldata[:4]) != string(method.ID) {
		return receipt, inclusion, idTimestamp, grant, fmt.Errorf("calldata is not publishCheckpoint")
	}
	values, err := method.Inputs.Unpack(calldata[4:])
	if err != nil {
		return receipt, inclusion, idTimestamp, grant, err
	}
	receipt = *abi.ConvertType(values[0], new(ConsistencyReceipt)).(*ConsistencyReceipt)
	inclusion = *abi.ConvertType(values[1], new(InclusionProof)).(*InclusionProof)
	idTimestamp = *abi.ConvertType(values[2], new([8]byte)).(*[8]byte)
	grant = *abi.ConvertType(values[3], new(PublishGrant)).(*PublishGrant)
	return receipt, inclusion, idTimestamp, grant, nil
}
