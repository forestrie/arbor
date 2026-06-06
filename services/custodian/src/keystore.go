package custodian

import (
	"sync"
)

// KeyStore caches selfLogId (32-hex KMS CryptoKey id) -> key info for this process.
// KMS is the source of truth; entries are populated after a successful ensure.
type KeyStore struct {
	mu   sync.RWMutex
	byID map[string]KeyInfo
}

// KeyInfo is stored per self log id.
type KeyInfo struct {
	KeyID        string // GCP crypto key resource name
	PublicKeyPEM string
	Alg          string
}

func NewKeyStore() *KeyStore {
	return &KeyStore{byID: make(map[string]KeyInfo)}
}

func (s *KeyStore) Get(selfLogID string) (KeyInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.byID[selfLogID]
	return info, ok
}

func (s *KeyStore) Set(selfLogID string, info KeyInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[selfLogID] = info
}
