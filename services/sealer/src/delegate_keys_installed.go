package sealer

import (
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
