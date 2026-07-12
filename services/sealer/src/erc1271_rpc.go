package sealer

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

var (
	erc1271ABI   abi.ABI
	erc1271Magic = [4]byte{0x16, 0x26, 0xba, 0x7e}
)

func init() {
	parsed, err := abi.JSON(strings.NewReader(`[{"inputs":[{"internalType":"bytes32","name":"hash","type":"bytes32"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"isValidSignature","outputs":[{"internalType":"bytes4","name":"","type":"bytes4"}],"stateMutability":"view","type":"function"}]`))
	if err != nil {
		panic(fmt.Sprintf("parse erc1271 abi: %v", err))
	}
	erc1271ABI = parsed
}

// RPCERC1271Verifier verifies KS256 Safe/contract signatures via eth_call.
type RPCERC1271Verifier struct {
	client *ethclient.Client
}

func NewRPCERC1271Verifier(rpcURL string) (*RPCERC1271Verifier, error) {
	rpcURL = strings.TrimSpace(rpcURL)
	if rpcURL == "" {
		return nil, fmt.Errorf("chain RPC URL is empty")
	}
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial chain RPC: %w", err)
	}
	return &RPCERC1271Verifier{client: client}, nil
}

func (v *RPCERC1271Verifier) HasCode(_ context.Context, addr []byte) (bool, error) {
	if v == nil || v.client == nil {
		return false, fmt.Errorf("erc1271 verifier not configured")
	}
	if len(addr) != 20 {
		return false, fmt.Errorf("address must be 20 bytes")
	}
	code, err := v.client.CodeAt(context.Background(), common.BytesToAddress(addr), nil)
	if err != nil {
		return false, err
	}
	return len(code) > 0, nil
}

func (v *RPCERC1271Verifier) IsValidSignature(_ context.Context, addr, hash, sig []byte) error {
	if v == nil || v.client == nil {
		return fmt.Errorf("erc1271 verifier not configured")
	}
	if len(hash) != 32 {
		return fmt.Errorf("hash must be 32 bytes")
	}
	var hash32 [32]byte
	copy(hash32[:], hash)
	data, err := erc1271ABI.Pack("isValidSignature", hash32, sig)
	if err != nil {
		return err
	}
	to := common.BytesToAddress(addr)
	msg := ethereum.CallMsg{To: &to, Data: data}
	out, err := v.client.CallContract(context.Background(), msg, nil)
	if err != nil {
		return err
	}
	vals, err := erc1271ABI.Unpack("isValidSignature", out)
	if err != nil || len(vals) == 0 {
		return fmt.Errorf("ERC-1271 isValidSignature rejected signature")
	}
	magic, ok := vals[0].([4]byte)
	if !ok || magic != erc1271Magic {
		return fmt.Errorf("ERC-1271 isValidSignature rejected signature")
	}
	return nil
}

var _ delegationcert.ERC1271Verifier = (*RPCERC1271Verifier)(nil)
