package publishproof

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// Selector pinned from the v0.1.5 release artifact methodIdentifiers:
//
//	eecac1b7 logState(bytes32)
const logStateSelectorHex = "eecac1b7"

type fakeCaller struct {
	t        *testing.T
	wantTo   common.Address
	calldata []byte
	ret      []byte
}

func (f *fakeCaller) CallContract(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
	require.NotNil(f.t, msg.To)
	require.Equal(f.t, f.wantTo, *msg.To)
	f.calldata = msg.Data
	return f.ret, nil
}

func TestReadLogStateDecodesAccumulatorAndSize(t *testing.T) {
	contract := common.HexToAddress("0x000000000000000000000000000000000000C0DE")
	logId := bytes32FromLow(t, "000102030405060708090a0b0c0d0e0f")
	peak := bytes32FromLow(t, "11")

	ret, err := univocityABI.Methods["logState"].Outputs.Pack(struct {
		Accumulator [][32]byte
		Size        uint64
	}{[][32]byte{peak}, 2})
	require.NoError(t, err)

	caller := &fakeCaller{t: t, wantTo: contract, ret: ret}
	state, err := ReadLogState(context.Background(), caller, contract, logId)
	require.NoError(t, err)

	require.Equal(t, uint64(2), state.Size)
	require.Equal(t, [][32]byte{peak}, state.Accumulator)
	require.Equal(t, logStateSelectorHex, hex.EncodeToString(caller.calldata[:4]))
	require.Equal(t, logId[:], caller.calldata[4:36])
}
