package univocity

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/arbor/services/pkgs/publishproof"
)

type mockChain struct {
	rootLogId                logid.UUID
	bootstrapAlg             int64
	bootstrapKey             []byte
	logInitialized           bool
	logConfig                LogConfig
	logRootKeyX, logRootKeyY [32]byte

	// logs overrides the single-log fields above per log id.
	mu    sync.Mutex
	logs  map[logid.UUID]mockLog
	calls int
	// bootstrapErr, when set, fails BootstrapConfig (an RPC outage).
	bootstrapErr error
	// block is the chain head; registrations are LogRegistered events.
	block         uint64
	registrations []LogRegistration
}

// emitRegistration mines a block carrying a LogRegistered event.
func (m *mockChain) emitRegistration(id, owner logid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.block++
	m.registrations = append(m.registrations, LogRegistration{LogID: id, GrantLogID: owner, Block: m.block})
}

func (m *mockChain) LatestBlock(context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.block, nil
}

func (m *mockChain) LogRegistrations(_ context.Context, from, to uint64) ([]LogRegistration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []LogRegistration
	for _, r := range m.registrations {
		if r.Block >= from && r.Block <= to {
			out = append(out, r)
		}
	}
	return out, nil
}

// mockLog is one log's on-chain record.
type mockLog struct {
	config LogConfig // Kind != Undefined means initialized
	state  publishproof.LogState
}

func (m *mockChain) setLog(id logid.UUID, l mockLog) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.logs == nil {
		m.logs = map[logid.UUID]mockLog{}
	}
	m.logs[id] = l
}

func (m *mockChain) log(id logid.UUID) (mockLog, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	l, ok := m.logs[id]
	return l, ok
}

// callCount returns the number of per-log chain reads so far.
func (m *mockChain) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *mockChain) RootLogId(context.Context) (logid.UUID, error) {
	return m.rootLogId, nil
}

func (m *mockChain) BootstrapConfig(context.Context) (int64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.bootstrapErr != nil {
		return 0, nil, m.bootstrapErr
	}
	return m.bootstrapAlg, m.bootstrapKey, nil
}

func (m *mockChain) IsLogInitialized(_ context.Context, id logid.UUID) (bool, error) {
	if l, ok := m.log(id); ok {
		return l.config.Kind != LogKindUndefined, nil
	}
	return m.logInitialized, nil
}

func (m *mockChain) LogConfig(_ context.Context, id logid.UUID) (LogConfig, error) {
	if l, ok := m.log(id); ok {
		return l.config, nil
	}
	return m.logConfig, nil
}

func (m *mockChain) LogState(_ context.Context, id logid.UUID) (publishproof.LogState, error) {
	l, _ := m.log(id)
	return l.state, nil
}

func (m *mockChain) LogRootKey(_ context.Context, _ logid.UUID) ([32]byte, [32]byte, error) {
	return m.logRootKeyX, m.logRootKeyY, nil
}

func (m *mockChain) HasCode(_ context.Context, _ common.Address) (bool, error) {
	return false, nil
}

func (m *mockChain) IsValidSignature(_ context.Context, _ common.Address, hash, sig []byte) error {
	return errERC1271Failed
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
