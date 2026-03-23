package custodian

import (
	"context"
	"crypto/sha256"
	"io"

	"github.com/veraison/go-cose"
)

// kmsCOSESigner implements cose.Signer using Cloud KMS AsymmetricSign (SHA-256 digest in).
type kmsCOSESigner struct {
	alg  cose.Algorithm
	ctx  context.Context
	sign func(context.Context, []byte) ([]byte, error)
}

func (s *kmsCOSESigner) Algorithm() cose.Algorithm { return s.alg }

// Sign hashes content with SHA-256 (COSE ES256 / ES256K) then signs the digest via KMS.
func (s *kmsCOSESigner) Sign(_ io.Reader, content []byte) ([]byte, error) {
	sum := sha256.Sum256(content)
	return s.sign(s.ctx, sum[:])
}
