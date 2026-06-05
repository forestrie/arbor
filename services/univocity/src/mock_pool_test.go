package univocity

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

type mockChain struct {
	rootLogId                [32]byte
	logInitialized           bool
	logConfig                LogConfig
	logRootKeyX, logRootKeyY [32]byte
}

func (m *mockChain) RootLogId(context.Context) ([32]byte, error) {
	return m.rootLogId, nil
}

func (m *mockChain) IsLogInitialized(_ context.Context, _ [32]byte) (bool, error) {
	return m.logInitialized, nil
}

func (m *mockChain) LogConfig(_ context.Context, _ [32]byte) (LogConfig, error) {
	return m.logConfig, nil
}

func (m *mockChain) LogRootKey(_ context.Context, _ [32]byte) ([32]byte, [32]byte, error) {
	return m.logRootKeyX, m.logRootKeyY, nil
}

type mockPool struct {
	mu    sync.Mutex
	chain *mockChain
}

func (p *mockPool) Reader(uint64, common.Address) (ChainReader, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.chain, nil
}

func (p *mockPool) Close() {}
