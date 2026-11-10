package univocity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/forestrie/arbor/services/pkgs/logid"
)

// SweepReservations removes reservations that no longer hold a log (devdocs
// ADR-0075 decision 2): those past their lapse time, those whose grant chain
// no longer reaches the bootstrap key because a reservation above them
// lapsed, and those a committed claim superseded. It repeats until a pass
// removes nothing, so a lapse takes the whole subtree beneath it. Reads
// already treat each of these as absent; the sweep only reclaims storage.
// It never touches a committed grant or the logId->R index.
func (a API) SweepReservations(ctx context.Context) (int, error) {
	if a.Store == nil {
		return 0, ErrStoreNotConfigured
	}
	removed := 0
	for range maxGrantChainDepth + 1 {
		ids, err := a.Store.ListReservations(ctx)
		if err != nil {
			return removed, err
		}
		pass := 0
		for _, id := range ids {
			gone, err := a.sweepReservation(ctx, id)
			if err != nil {
				a.Logger.Warn("reservation sweep skipped a log", "logId", id.String(), "error", err)
				continue
			}
			if gone {
				pass++
			}
		}
		removed += pass
		if pass == 0 {
			return removed, nil
		}
	}
	return removed, nil
}

// sweepReservation removes subject's reservation if it no longer holds the
// log. Errors that do not prove the reservation dead (an unreadable store or
// chain) leave it in place.
func (a API) sweepReservation(ctx context.Context, subject logid.UUID) (bool, error) {
	defer lockSubject(subject)()
	res, held, err := a.readReservation(ctx, subject)
	if err != nil || !held {
		return false, err
	}
	dead, err := a.reservationDead(ctx, subject, res)
	if err != nil || !dead {
		return false, err
	}
	if err := a.Store.DeleteReservation(ctx, subject); err != nil {
		return false, fmt.Errorf("delete reservation: %w", err)
	}
	a.Logger.Info("reservation removed", "logId", subject.String(), "R", res.root.String())
	return true, nil
}

func (a API) reservationDead(ctx context.Context, subject logid.UUID, res reservation) (bool, error) {
	if !res.live(a.now()) {
		return true, nil
	}
	if _, err := a.Store.GetGrant(ctx, res.root, subject); err == nil {
		return true, nil // superseded by a committed claim
	} else if !isStoreMiss(err) {
		return false, err
	}
	ts, err := decodeTransparentStatement(res.statement)
	if err != nil {
		return true, nil
	}
	forest, err := a.loadForest(ctx, res.root)
	if isStoreMiss(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	_, reader, err := a.withReader(forest)
	if err != nil {
		return false, err
	}
	err = a.verifyGrantChain(ctx, forest, reader, ts)
	if errors.Is(err, errNoClaim) || errors.Is(err, ErrGrantSignatureInvalid) {
		return true, nil
	}
	return false, err
}

// RunReservationSweeper sweeps lapsed reservations every interval until ctx
// ends.
func (a API) RunReservationSweeper(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := a.SweepReservations(ctx); err != nil {
				a.Logger.Warn("reservation sweep failed", "error", err)
			} else if n > 0 {
				a.Logger.Info("reservation sweep", "removed", n)
			}
		}
	}
}
