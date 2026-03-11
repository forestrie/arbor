package univocity

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

const univocityViewABI = `[
	{"inputs":[],"name":"rootLogId","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},
	{"inputs":[{"internalType":"bytes32","name":"logId","type":"bytes32"}],"name":"logConfig","outputs":[{"internalType":"uint8","name":"kind","type":"uint8"},{"internalType":"bytes32","name":"authLogId","type":"bytes32"},{"internalType":"bytes","name":"rootKey","type":"bytes"},{"internalType":"uint256","name":"initializedAt","type":"uint256"}],"stateMutability":"view","type":"function"},
	{"inputs":[{"internalType":"bytes32","name":"logId","type":"bytes32"}],"name":"isLogInitialized","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},
	{"inputs":[{"internalType":"bytes32","name":"logId","type":"bytes32"}],"name":"logRootKey","outputs":[{"internalType":"bytes32","name":"rootKeyX","type":"bytes32"},{"internalType":"bytes32","name":"rootKeyY","type":"bytes32"}],"stateMutability":"view","type":"function"}
]`

type LogKind uint8

const (
	LogKindUndefined LogKind = iota
	LogKindAuthority
	LogKindData
)

func (k LogKind) String() string {
	switch k {
	case LogKindAuthority:
		return "authority"
	case LogKindData:
		return "data"
	default:
		return "undefined"
	}
}

type LogConfig struct {
	Kind          LogKind
	AuthLogId     [32]byte
	RootKey       []byte
	InitializedAt uint64
}

type UnivocityContract struct {
	client   *ethclient.Client
	addr     common.Address
	contract abi.ABI
}

func NewUnivocityContract(rpcURL, contractAddr string) (*UnivocityContract, error) {
	if rpcURL == "" || contractAddr == "" {
		return nil, errors.New("UNIVOCITY_RPC_URL and UNIVOCITY_CONTRACT_ADDRESS are required")
	}
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, err
	}
	contract, err := abi.JSON(strings.NewReader(univocityViewABI))
	if err != nil {
		client.Close()
		return nil, err
	}
	addr := common.HexToAddress(contractAddr)
	return &UnivocityContract{client: client, addr: addr, contract: contract}, nil
}

func (c *UnivocityContract) Close() {
	c.client.Close()
}

func (c *UnivocityContract) RootLogId(ctx context.Context) ([32]byte, error) {
	data, err := c.contract.Pack("rootLogId")
	if err != nil {
		return [32]byte{}, err
	}
	out, err := c.call(ctx, data)
	if err != nil {
		return [32]byte{}, err
	}
	vals, err := c.contract.Unpack("rootLogId", out)
	if err != nil || len(vals) == 0 {
		return [32]byte{}, err
	}
	return vals[0].([32]byte), nil
}

func (c *UnivocityContract) IsLogInitialized(ctx context.Context, logId [32]byte) (bool, error) {
	data, err := c.contract.Pack("isLogInitialized", logId)
	if err != nil {
		return false, err
	}
	out, err := c.call(ctx, data)
	if err != nil {
		return false, err
	}
	vals, err := c.contract.Unpack("isLogInitialized", out)
	if err != nil || len(vals) == 0 {
		return false, err
	}
	return vals[0].(bool), nil
}

func (c *UnivocityContract) LogConfig(ctx context.Context, logId [32]byte) (LogConfig, error) {
	data, err := c.contract.Pack("logConfig", logId)
	if err != nil {
		return LogConfig{}, err
	}
	out, err := c.call(ctx, data)
	if err != nil {
		return LogConfig{}, err
	}
	vals, err := c.contract.Unpack("logConfig", out)
	if err != nil || len(vals) < 4 {
		return LogConfig{}, err
	}
	cfg := LogConfig{}
	if v, ok := vals[0].(uint8); ok {
		cfg.Kind = LogKind(v)
	}
	if v, ok := vals[1].([32]byte); ok {
		cfg.AuthLogId = v
	}
	if v, ok := vals[2].([]byte); ok {
		cfg.RootKey = v
	}
	if v, ok := vals[3].(*big.Int); ok && v != nil && v.IsUint64() {
		cfg.InitializedAt = v.Uint64()
	}
	return cfg, nil
}

func (c *UnivocityContract) LogRootKey(ctx context.Context, logId [32]byte) (rootKeyX, rootKeyY [32]byte, err error) {
	data, err := c.contract.Pack("logRootKey", logId)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	out, err := c.call(ctx, data)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	vals, err := c.contract.Unpack("logRootKey", out)
	if err != nil || len(vals) < 2 {
		return [32]byte{}, [32]byte{}, err
	}
	rootKeyX = vals[0].([32]byte)
	rootKeyY = vals[1].([32]byte)
	return rootKeyX, rootKeyY, nil
}

func (c *UnivocityContract) call(ctx context.Context, data []byte) ([]byte, error) {
	msg := ethereum.CallMsg{
		To:   &c.addr,
		Data: data,
	}
	return c.client.CallContract(ctx, msg, nil)
}

func LogIDFromHex(s string) ([32]byte, bool) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) > 32 {
		return [32]byte{}, false
	}
	var id [32]byte
	copy(id[32-len(decoded):], decoded)
	return id, true
}

func LogIDToHex(id [32]byte) string {
	return "0x" + hex.EncodeToString(id[:])
}
