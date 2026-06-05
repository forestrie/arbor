package univocity

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

var ErrChainNotConfigured = errors.New("chainId not configured")

// ChainResolver returns a ChainReader for a (chainId, contract) pair.
type ChainResolver interface {
	Reader(chainID uint64, contractAddr common.Address) (ChainReader, error)
	Close()
}

// ContractClients lazily dials one ethclient per configured chainId.
type ContractClients struct {
	mu       sync.Mutex
	rpcURLs  map[uint64]string
	clients  map[uint64]*ethclient.Client
	contract abi.ABI
}

// NewContractClients builds a resolver pool from chainId -> rpc url map.
func NewContractClients(rpcURLs map[uint64]string) (*ContractClients, error) {
	contract, err := abi.JSON(strings.NewReader(univocityViewABI))
	if err != nil {
		return nil, err
	}
	return &ContractClients{
		rpcURLs:  rpcURLs,
		clients:  make(map[uint64]*ethclient.Client),
		contract: contract,
	}, nil
}

func (p *ContractClients) Reader(
	chainID uint64,
	contractAddr common.Address,
) (ChainReader, error) {
	url, ok := p.rpcURLs[chainID]
	if !ok {
		return nil, ErrChainNotConfigured
	}
	client, err := p.clientForChain(chainID, url)
	if err != nil {
		return nil, err
	}
	return &UnivocityContract{
		client:   client,
		addr:     contractAddr,
		contract: p.contract,
	}, nil
}

func (p *ContractClients) clientForChain(chainID uint64, url string) (*ethclient.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[chainID]; ok {
		return c, nil
	}
	client, err := ethclient.Dial(url)
	if err != nil {
		return nil, err
	}
	p.clients[chainID] = client
	return client, nil
}

func (p *ContractClients) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.clients {
		c.Close()
	}
	p.clients = make(map[uint64]*ethclient.Client)
}

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

// ChainReader is the contract read interface used by the API. It allows tests to inject a mock.
type ChainReader interface {
	RootLogId(ctx context.Context) ([32]byte, error)
	IsLogInitialized(ctx context.Context, logId [32]byte) (bool, error)
	LogConfig(ctx context.Context, logId [32]byte) (LogConfig, error)
	LogRootKey(ctx context.Context, logId [32]byte) (rootKeyX, rootKeyY [32]byte, err error)
}

type UnivocityContract struct {
	client   *ethclient.Client
	addr     common.Address
	contract abi.ABI
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
