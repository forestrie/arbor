package custodian

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"

	"github.com/veraison/go-cose"
)

// kmsCOSESigner implements cose.Signer using Cloud KMS AsymmetricSign (SHA-256 digest in).
type kmsCOSESigner struct {
	alg       cose.Algorithm
	ctx       context.Context
	sign      func(context.Context, []byte) ([]byte, error)
	log       *slog.Logger // optional; Sign logs Sig_structure digest for cross-check with Canopy
	signKeyID string       // HTTP key id (e.g. ":bootstrap") when log != nil
}

func (s *kmsCOSESigner) Algorithm() cose.Algorithm { return s.alg }

// Sign hashes content with SHA-256 (COSE ES256 / ES256K) then signs the digest via KMS.
// Content is the CBOR-encoded Sig_structure from go-cose (RFC 8152 §4.4); kmsAsymmetricSignSHA256
// sends sha256(content) as Digest.Sha256 — same inputs as Canopy verifyCoseSign1 (see
// sig_structure_digest_audit_test.go).
func (s *kmsCOSESigner) Sign(_ io.Reader, content []byte) ([]byte, error) {
	sum := sha256.Sum256(content)
	if s.log != nil {
		// First 8 bytes of SHA-256(ToBeSigned), 16 hex chars — same convention as Canopy
		// verifyCoseSign1Failure.sigStructureSha256HexPrefix (see packages/shared/encoding).
		s.log.Warn("custodian Sign1 ToBeSigned digest",
			"tag", "custodianSign1ToBeSignedDigest",
			"keyId", s.signKeyID,
			"sigStructureLen", len(content),
			"sigStructureSha256HexPrefix", hex.EncodeToString(sum[:8]),
		)
	}
	return s.sign(s.ctx, sum[:])
}
