package custodian

import (
	"sync"
)

// KeyStore holds key_owner_id -> key info (in-memory for MVP).
type KeyStore struct {
	mu   sync.RWMutex
	byID map[string]KeyInfo
}

// KeyInfo is stored per key owner.
type KeyInfo struct {
	KeyID      string // GCP crypto key resource id or short id
	PublicKeyPEM string
	Alg        string
}

func NewKeyStore() *KeyStore {
	return &KeyStore{byID: make(map[string]KeyInfo)}
}

func (s *KeyStore) Get(keyOwnerID string) (KeyInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.byID[keyOwnerID]
	return info, ok
}

func (s *KeyStore) Set(keyOwnerID string, info KeyInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[keyOwnerID] = info
}

func (s *KeyStore) GetByKeyID(keyID string) (KeyInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, info := range s.byID {
		if info.KeyID == keyID {
			return info, true
		}
	}
	return KeyInfo{}, false
}
