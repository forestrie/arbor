package univocity

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// maxRegistrationSpan bounds the block range of one LogRegistered query.
const maxRegistrationSpan = 2000

// registrationLookback is how far before the head a contract's first poll
// starts, so registrations between univocity loading the forest and that
// poll are not skipped. Seeing an event twice is harmless.
const registrationLookback = 256

// RegistrationWatcher follows each forest contract's LogRegistered events
// so a claimed log is compared with its first checkpoint as soon as it is
// registered (devdocs ADR-0075 decision 8). Contracts are watched from
// shortly before the head at univocity's first poll after loading their
// forest; a log registered earlier is compared when its authority is next
// computed.
type RegistrationWatcher struct {
	mu        sync.Mutex
	contracts map[watchedKey]*watchedContract
}

type watchedKey struct {
	chainID  uint64
	contract common.Address
}

type watchedContract struct {
	forest  ForestEntry
	cursor  uint64 // last block processed
	started bool
}

// NewRegistrationWatcher returns a watcher with no contracts.
func NewRegistrationWatcher() *RegistrationWatcher {
	return &RegistrationWatcher{contracts: map[watchedKey]*watchedContract{}}
}

func (w *RegistrationWatcher) watch(forest ForestEntry) {
	if w == nil {
		return
	}
	k := watchedKey{chainID: forest.ChainID, contract: forest.Contract}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.contracts[k]; !ok {
		w.contracts[k] = &watchedContract{forest: forest}
	}
}

func (w *RegistrationWatcher) snapshot() []*watchedContract {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]*watchedContract, 0, len(w.contracts))
	for _, c := range w.contracts {
		out = append(out, c)
	}
	return out
}

// RunRegistrationWatcher polls watched contracts every interval until ctx
// ends.
func (a API) RunRegistrationWatcher(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.pollRegistrations(ctx)
		}
	}
}

// pollRegistrations processes LogRegistered events since each contract's
// cursor. Polls are serial (one goroutine), so cursors need no lock.
func (a API) pollRegistrations(ctx context.Context) {
	if a.Registrations == nil || a.Pool == nil {
		return
	}
	for _, c := range a.Registrations.snapshot() {
		if err := a.pollContract(ctx, c); err != nil {
			a.Logger.Warn("LogRegistered poll failed",
				"chainId", c.forest.ChainID, "contract", c.forest.Contract.Hex(), "error", err)
		}
	}
}

func (a API) pollContract(ctx context.Context, c *watchedContract) error {
	reader, err := a.Pool.Reader(c.forest.ChainID, c.forest.Contract)
	if err != nil {
		return err
	}
	head, err := reader.LatestBlock(ctx)
	if err != nil {
		return err
	}
	if !c.started {
		c.cursor, c.started = head-min(head, registrationLookback), true
	}
	for c.cursor < head {
		to := min(head, c.cursor+maxRegistrationSpan)
		regs, err := reader.LogRegistrations(ctx, c.cursor+1, to)
		if err != nil {
			return err
		}
		for _, reg := range regs {
			a.onRegistration(ctx, c.forest, reg)
		}
		c.cursor = to
	}
	return nil
}

// onRegistration recomputes a claimed log's authority at its first
// checkpoint, which compares the chain's record with the claim, unless its
// answer is already final. Logs this instance has not claimed are ignored.
// A root registration (the log is its own grant log) also drops the pending
// answers of every root bound to the contract: it is now the contract's
// root, and any other is conflicted.
func (a API) onRegistration(ctx context.Context, forest ForestEntry, reg LogRegistration) {
	if reg.LogID == reg.GrantLogID {
		a.Authorities.evictPendingRoots(forest.ChainID, forest.Contract)
	}
	a.Authorities.evict(reg.LogID)
	x, err := a.resolveAuthority(ctx, reg.LogID, forest.R)
	if errors.Is(err, ErrLogNotResolved) {
		return
	}
	if err != nil {
		a.Logger.Warn("authority at registration failed", "logId", reg.LogID.String(), "error", err)
		return
	}
	a.Logger.Info("log registered on chain", "logId", reg.LogID.String(),
		"grantLogId", reg.GrantLogID.String(), "state", x.State)
}
