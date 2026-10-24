package sealer

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
)

// DelegateKeyReadiness is the sealer's readiness latch (devdocs plan-2609-12
// ruling 5 and ruling D1 (a); slice 05:
// https://github.com/forestrie/devdocs/blob/main/plans/plan-2609-12-delegate-key-registration-hardening/05-sealer-readiness.md).
// It is Ready once the standing delegate keys are installed and the
// coordinator has accepted one assertion of the current key, and then stays
// Ready for the life of the process: after boot, a lost registration shows
// on sealer_delegate_key_registered, not on /readyz. main serves /readyz from
// it and starts the queue consumer and resync only once it is Ready, so a pod
// that cannot load or register its keys does no work and a rollout keeps the
// previous pod.
type DelegateKeyReadiness struct {
	installed atomic.Bool
	ready     chan struct{}
	once      sync.Once
}

// NewDelegateKeyReadiness returns a latch that is neither installed nor Ready.
func NewDelegateKeyReadiness() *DelegateKeyReadiness {
	return &DelegateKeyReadiness{ready: make(chan struct{})}
}

func (r *DelegateKeyReadiness) markInstalled() { r.installed.Store(true) }

func (r *DelegateKeyReadiness) markReady() {
	r.installed.Store(true)
	r.once.Do(func() { close(r.ready) })
}

// Installed reports whether the standing delegate keys are installed.
func (r *DelegateKeyReadiness) Installed() bool { return r.installed.Load() }

// Done is closed once the sealer is Ready.
func (r *DelegateKeyReadiness) Done() <-chan struct{} { return r.ready }

// Ready reports whether the latch has fired.
func (r *DelegateKeyReadiness) Ready() bool {
	select {
	case <-r.ready:
		return true
	default:
		return false
	}
}

// RunWhenReady calls start once, in a new goroutine, after the sealer is
// Ready, unless ctx is cancelled first. The returned channel is closed when
// that goroutine exits, whether or not start ran. main uses it to start the
// queue consumer and resync.
func (r *DelegateKeyReadiness) RunWhenReady(ctx context.Context, start func()) <-chan struct{} {
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
		case <-r.ready:
			if ctx.Err() == nil {
				start()
			}
		}
	}()
	return exited
}

// ReadyzHandler answers 200 once Ready and 503, with the reason, before.
func (r *DelegateKeyReadiness) ReadyzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		switch {
		case r.Ready():
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready"))
		case !r.Installed():
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("delegate keys not installed"))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("current delegate key not yet asserted with the coordinator"))
		}
	}
}
