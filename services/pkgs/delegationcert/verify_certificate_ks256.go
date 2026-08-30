package delegationcert

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// ERC1271Verifier supports KS256 contract-wallet signature checks (Safe, etc.).
type ERC1271Verifier interface {
	HasCode(ctx context.Context, addr []byte) (bool, error)
	IsValidSignature(ctx context.Context, addr, hash, sig []byte) error
}

// VerifyCertificateSignatureKS256 verifies a delegation certificate COSE Sign1
// KS256 signature against a 20-byte Ethereum root signer using keccak256
// Sig_structure + ecrecover or ERC-1271.
func VerifyCertificateSignatureKS256(
	certBytes []byte,
	rootSigner []byte,
	erc1271 ERC1271Verifier,
) error {
	if len(certBytes) == 0 {
		return fmt.Errorf("empty certificate")
	}
	if len(rootSigner) != 20 {
		return fmt.Errorf("KS256 root signer must be 20 bytes, got %d", len(rootSigner))
	}

	parts, err := decodeCertificate(certBytes)
	if err != nil {
		return err
	}
	alg, err := algFromParts(parts)
	if err != nil {
		return err
	}
	if alg != CoseAlgKS256 {
		return fmt.Errorf("delegation cert alg %d is not KS256", alg)
	}
	// KS256 defines no alg-specific material, so a WebAuthn envelope here
	// is confusion and must be rejected BEFORE any signature work. This
	// entry point is separate from VerifyCertificateSignature, so the
	// guard is repeated rather than inherited — that separation is
	// exactly how the envelope previously rode through this path
	// untouched.
	if err := rejectStrayWebAuthnEnvelope(alg, parts); err != nil {
		return err
	}

	signature := parts.Signature
	sigStructureBytes, err := buildSigStructure(parts)
	if err != nil {
		return err
	}
	hash := crypto.Keccak256(sigStructureBytes)

	if erc1271 != nil {
		hasCode, err := erc1271.HasCode(context.Background(), rootSigner)
		if err != nil {
			return fmt.Errorf("erc1271 code check: %w", err)
		}
		if hasCode {
			if err := erc1271.IsValidSignature(context.Background(), rootSigner, hash, signature); err != nil {
				return fmt.Errorf("delegation cert signature invalid: %w", err)
			}
			return nil
		}
	}

	if len(signature) != 65 {
		return fmt.Errorf("KS256 EOA signature must be 65 bytes, got %d", len(signature))
	}
	pub, err := crypto.SigToPub(hash, signature)
	if err != nil {
		return fmt.Errorf("ecrecover failed: %w", err)
	}
	recovered := crypto.PubkeyToAddress(*pub)
	if !bytes.Equal(recovered.Bytes(), rootSigner) {
		return fmt.Errorf("delegation cert signer != KS256 root")
	}
	return nil
}
