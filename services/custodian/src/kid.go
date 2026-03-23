package custodian

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
)

// KidFromECDSAPublicKey returns the first 16 bytes of SHA-256(uncompressed EC point),
// matching sealer kidFromECDSAPublicKey (elliptic.Marshal).
func KidFromECDSAPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	if pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	uncompressed := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	sum := sha256.Sum256(uncompressed)
	kid := make([]byte, 16)
	copy(kid, sum[:16])
	return kid, nil
}
