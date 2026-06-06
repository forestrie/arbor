package univocity

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
)

type mockChain struct {
	rootLogId                logid.UUID
	bootstrapAlg             int64
	bootstrapKey             []byte
	logInitialized           bool
	logConfig                LogConfig
	logRootKeyX, logRootKeyY [32]byte
}

func (m *mockChain) RootLogId(context.Context) (logid.UUID, error) {
	return m.rootLogId, nil
}

func (m *mockChain) BootstrapConfig(context.Context) (int64, []byte, error) {
	return m.bootstrapAlg, m.bootstrapKey, nil
}

func (m *mockChain) IsLogInitialized(_ context.Context, _ logid.UUID) (bool, error) {
	return m.logInitialized, nil
}

func (m *mockChain) LogConfig(_ context.Context, _ logid.UUID) (LogConfig, error) {
	return m.logConfig, nil
}

func (m *mockChain) LogRootKey(_ context.Context, _ logid.UUID) ([32]byte, [32]byte, error) {
	return m.logRootKeyX, m.logRootKeyY, nil
}

type mockPool struct {
	mu    sync.Mutex
	chain ChainReader
}

func (p *mockPool) Reader(uint64, common.Address) (ChainReader, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.chain, nil
}

func (p *mockPool) Close() {}
