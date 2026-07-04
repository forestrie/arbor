package publishproof

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// LogState mirrors the univocity LogState return tuple: the MMR accumulator
// peaks and the anchored size for a log.
type LogState struct {
	Accumulator [][32]byte
	Size        uint64
}

// ContractCaller is the read-only subset of ethclient.Client used by
// publishproof; it allows tests and callers to supply any eth_call backend.
type ContractCaller interface {
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

// ReadLogState reads logState(logId) from the univocity contract at the
// latest block. A never-published log returns the zero LogState.
func ReadLogState(
	ctx context.Context,
	caller ContractCaller,
	contract common.Address,
	logId [32]byte,
) (LogState, error) {
	data, err := univocityABI.Pack("logState", logId)
	if err != nil {
		return LogState{}, err
	}
	out, err := caller.CallContract(ctx, ethereum.CallMsg{To: &contract, Data: data}, nil)
	if err != nil {
		return LogState{}, fmt.Errorf("logState call: %w", err)
	}
	values, err := univocityABI.Unpack("logState", out)
	if err != nil {
		return LogState{}, fmt.Errorf("logState decode: %w", err)
	}
	return *abi.ConvertType(values[0], new(LogState)).(*LogState), nil
}
