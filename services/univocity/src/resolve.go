package univocity

import (
	"context"
	"errors"
	"fmt"

	"github.com/forestrie/arbor/services/pkgs/logid"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// ErrLogNotResolved reports a logId this instance has no locator for. The HTTP
// boundary maps it to 404 with remediation guidance (plan-2607-10 D5): supply
// a verified rootLogId hint or use the chain-scoped routes. It is never a
// service-availability condition.
var ErrLogNotResolved = errors.New("log id not resolved to a forest")

func isStoreMiss(err error) bool {
	return errors.Is(err, massifstorage.ErrDoesNotExist)
}

// notResolvedError decorates ErrLogNotResolved with the ids involved so
// problem-details can name them — a wrong hint must not read as "log does
// not exist" (plan-2607-10 slice 02).
type notResolvedError struct{ detail string }

func (e *notResolvedError) Error() string { return e.detail }
func (e *notResolvedError) Unwrap() error { return ErrLogNotResolved }

func notResolved(format string, args ...any) error {
	return &notResolvedError{detail: fmt.Sprintf(format, args...)}
}

// resolveForestForLog finds the forest for a subject log by point lookups
// only: locator index, then the derived-key genesis (R case), or a
// caller-supplied verified hint. There is no enumeration fallback
// (plan-2607-10): an unknown logId is ErrLogNotResolved, never a scan. The
// chain allow-list is enforced by Pool.Reader (ErrChainNotConfigured), which
// previously happened as a registry scan filter.
func (a API) resolveForestForLog(
	ctx context.Context,
	logID logid.UUID,
	hint logid.UUID,
) (ForestEntry, ChainReader, error) {
	if a.Store == nil {
		return ForestEntry{}, nil, ErrStoreNotConfigured
	}
	if !hint.IsZero() {
		forest, err := a.resolveWithHint(ctx, logID, hint)
		if err != nil {
			return ForestEntry{}, nil, err
		}
		return a.withReader(forest)
	}
	if a.Forests != nil {
		if e, ok, neg := a.Forests.Get(logID); neg {
			return ForestEntry{}, nil, notResolved(
				"log %s is not indexed by this univocity instance", logID)
		} else if ok {
			return a.withReader(e)
		}
	}
	if r, found, err := a.Store.IndexGet(ctx, logID); err != nil {
		return ForestEntry{}, nil, fmt.Errorf("index lookup: %w", err)
	} else if found {
		forest, err := a.loadForest(ctx, r)
		if err == nil {
			a.cachePositive(logID, forest)
			return a.withReader(forest)
		}
		if !isStoreMiss(err) {
			return ForestEntry{}, nil, fmt.Errorf("load forest for index: %w", err)
		}
		// Dangling locator (plan-2607-10 D7): the index names a forest whose
		// genesis is gone (delete paths, pruning). Self-heal and continue as
		// a miss — stale locators must never surface as availability errors.
		if derr := a.Store.DeleteIndex(ctx, logID); derr != nil {
			a.Logger.Warn("dangling index self-heal failed",
				"logId", logID.String(), "R", r.String(), "error", derr)
		} else {
			a.Logger.Warn("removed dangling index entry",
				"logId", logID.String(), "R", r.String())
		}
	}
	// R case: a forest root resolves by its derived genesis key even with no
	// index entry (canopy writes genesis directly when the forward is unarmed).
	forest, err := a.loadForest(ctx, logID)
	if err == nil {
		if _, _, ierr := a.Store.IndexCreate(ctx, logID, logID); ierr != nil {
			a.Logger.Warn("R self-index heal failed", "R", logID.String(), "error", ierr)
		}
		a.cachePositive(logID, forest)
		return a.withReader(forest)
	}
	if !isStoreMiss(err) {
		return ForestEntry{}, nil, fmt.Errorf("load forest: %w", err)
	}
	if a.Forests != nil {
		a.Forests.PutNegative(logID)
	}
	return ForestEntry{}, nil, notResolved(
		"log %s is not indexed by this univocity instance", logID)
}

// resolveWithHint verifies a caller-supplied rootLogId locator: the hinted
// forest must exist and the log must have a stored grant in it (or be the
// forest root itself). The hint replaces discovery, not verification — the
// endpoint's chain-anchored checks still run downstream exactly as for an
// index hit (plan-2607-10 D2).
func (a API) resolveWithHint(
	ctx context.Context,
	logID, hint logid.UUID,
) (ForestEntry, error) {
	forest, err := a.loadForest(ctx, hint)
	if err != nil {
		if isStoreMiss(err) {
			return ForestEntry{}, notResolved(
				"hinted forest %s is unknown to this univocity instance", hint)
		}
		return ForestEntry{}, fmt.Errorf("load hinted forest: %w", err)
	}
	if logID == hint {
		a.cachePositive(logID, forest)
		return forest, nil
	}
	if _, err := a.Store.GetGrant(ctx, hint, logID); err != nil {
		if isStoreMiss(err) {
			return ForestEntry{}, notResolved(
				"log %s has no stored grant in hinted forest %s", logID, hint)
		}
		return ForestEntry{}, fmt.Errorf("hinted grant lookup: %w", err)
	}
	a.cachePositive(logID, forest)
	return forest, nil
}

func (a API) withReader(forest ForestEntry) (ForestEntry, ChainReader, error) {
	if a.Pool == nil {
		return ForestEntry{}, nil, fmt.Errorf("rpc pool not configured: %w", ErrChainNotConfigured)
	}
	reader, err := a.Pool.Reader(forest.ChainID, forest.Contract)
	if err != nil {
		return ForestEntry{}, nil, err
	}
	return forest, reader, nil
}

func (a API) cachePositive(logID logid.UUID, e ForestEntry) {
	if a.Forests != nil {
		a.Forests.PutPositive(logID, e)
	}
}
