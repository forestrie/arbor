package delegationcert

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fxamacker/cbor/v2"
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

	protectedBytes, payloadBytes, signature, err := decodeCoseSign1Parts(certBytes)
	if err != nil {
		return err
	}
	alg, err := ks256AlgFromProtectedHeader(protectedBytes)
	if err != nil {
		return err
	}
	if alg != CoseAlgKS256 {
		return fmt.Errorf("delegation cert alg %d is not KS256", alg)
	}

	sigStructure := []any{
		"Signature1",
		protectedBytes,
		[]byte{},
		payloadBytes,
	}
	sigStructureBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("encode sig structure: %w", err)
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

func decodeCoseSign1Parts(certBytes []byte) (protected, payload, signature []byte, err error) {
	var coseArr []any
	if err := cbor.Unmarshal(certBytes, &coseArr); err != nil {
		return nil, nil, nil, fmt.Errorf("decode COSE Sign1: %w", err)
	}
	if len(coseArr) != 4 {
		return nil, nil, nil, fmt.Errorf("unexpected COSE Sign1 array length: %d", len(coseArr))
	}
	protectedBytes, ok := asBstr(coseArr[0])
	if !ok {
		return nil, nil, nil, fmt.Errorf("COSE protected header is not bstr")
	}
	payloadBytes, ok := asBstr(coseArr[2])
	if !ok {
		return nil, nil, nil, fmt.Errorf("COSE payload is not bstr")
	}
	sigBytes, ok := asBstr(coseArr[3])
	if !ok {
		return nil, nil, nil, fmt.Errorf("COSE signature is not bstr")
	}
	return protectedBytes, payloadBytes, sigBytes, nil
}

func ks256AlgFromProtectedHeader(protected []byte) (int64, error) {
	protectedMap, err := decodeIntKeyedMap(protected)
	if err != nil {
		return 0, fmt.Errorf("decode protected header: %w", err)
	}
	alg, ok := asInt64(protectedMap[CoseHeaderAlg])
	if !ok {
		return 0, fmt.Errorf("protected header missing alg")
	}
	return alg, nil
}
