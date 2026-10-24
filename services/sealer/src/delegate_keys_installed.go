package sealer

import (
	"context"
	"net/http"
	"sync"
)

// DelegateKeysInstalled is the sealer's boot gate (devdocs plan-2609-12
// ruling D1 (a), slice 10). It fires once the standing delegate keys are
// installed in the lease manager. main starts the queue consumer and resync
// only after it fires, and /readyz answers 503 until then, so a pod that
// cannot load its keys does no work and a rollout keeps the previous pod.
type DelegateKeysInstalled struct {
	done chan struct{}
	once sync.Once
}

// NewDelegateKeysInstalled returns a gate that has not fired.
func NewDelegateKeysInstalled() *DelegateKeysInstalled {
	return &DelegateKeysInstalled{done: make(chan struct{})}
}

func (l *DelegateKeysInstalled) fire() {
	l.once.Do(func() { close(l.done) })
}

// Done is closed once the keys are installed.
func (l *DelegateKeysInstalled) Done() <-chan struct{} {
	return l.done
}

// Installed reports whether the keys are installed.
func (l *DelegateKeysInstalled) Installed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// RunWhenInstalled calls start once, in a new goroutine, after the keys are
// installed, unless ctx is cancelled first. The returned channel is closed
// when that goroutine exits, whether or not start ran. main uses it to start
// the queue consumer and resync.
func (l *DelegateKeysInstalled) RunWhenInstalled(ctx context.Context, start func()) <-chan struct{} {
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
		case <-l.done:
			if ctx.Err() == nil {
				start()
			}
		}
	}()
	return exited
}

// ReadyzHandler answers 200 once the keys are installed and 503 before.
func (l *DelegateKeysInstalled) ReadyzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if !l.Installed() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("delegate keys not installed"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}
}
