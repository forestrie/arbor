package custodian

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/veraison/go-cose"
)

// captureSigner records the exact byte string go-cose passes to Signer.Sign — the
// CBOR-encoded Sig_structure from RFC 8152 §4.4 (same construction ToBeSigned as
// Canopy's encodeSigStructure over protected bstr, external_aad, payload bstr).
type captureSigner struct {
	alg     cose.Algorithm
	content []byte
}

func (c *captureSigner) Algorithm() cose.Algorithm { return c.alg }

func (c *captureSigner) Sign(_ io.Reader, content []byte) ([]byte, error) {
	c.content = append([]byte(nil), content...)
	return make([]byte, 64), nil
}

// TestSign1_ToBeSigned_IsCBORArray4 documents go-cose Sign1 signing input shape.
func TestSign1_ToBeSigned_IsCBORArray4(t *testing.T) {
	kid := make([]byte, 16)
	for i := range kid {
		kid[i] = byte(i + 1)
	}
	payload := make([]byte, 32)
	for i := range payload {
		payload[i] = byte(i)
	}

	cap := &captureSigner{alg: cose.AlgorithmES256}
	msg := cose.NewSign1Message()
	msg.Headers.Protected = cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
		cose.HeaderLabelContentType: custodianStatementCTY,
		cose.HeaderLabelKeyID:       kid,
	}
	msg.Payload = payload

	if err := msg.Sign(rand.Reader, nil, cap); err != nil {
		t.Fatal(err)
	}
	if len(cap.content) == 0 || cap.content[0] != 0x84 {
		t.Fatalf("Sig_structure must be CBOR array(4); got len=%d first=0x%02x",
			len(cap.content), cap.content[0])
	}
}

// TestKMSCOSESigner_hashesSHA256OfSigStructure proves the digest sent to KMS is
// SHA-256(ToBeSigned) where ToBeSigned is the same CBOR Sig_structure bytes
// go-cose passes to Sign — matching Cloud KMS EC_SIGN_P256_SHA256 (digest in) and
// Canopy verifyCoseSign1 (Web Crypto ES256 over SHA-256 of those Sig_structure bytes).
func TestKMSCOSESigner_hashesSHA256OfSigStructure(t *testing.T) {
	kid := make([]byte, 16)
	payload := make([]byte, 32)

	cap := &captureSigner{alg: cose.AlgorithmES256}
	msgPlain := cose.NewSign1Message()
	msgPlain.Headers.Protected = cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
		cose.HeaderLabelContentType: custodianStatementCTY,
		cose.HeaderLabelKeyID:       kid,
	}
	msgPlain.Payload = payload
	if err := msgPlain.Sign(rand.Reader, nil, cap); err != nil {
		t.Fatal(err)
	}
	toBeSigned := cap.content
	wantDigest := sha256.Sum256(toBeSigned)

	var gotDigest []byte
	kmsSigner := &kmsCOSESigner{
		alg: cose.AlgorithmES256,
		ctx: context.Background(),
		sign: func(_ context.Context, digest []byte) ([]byte, error) {
			gotDigest = append([]byte(nil), digest...)
			return make([]byte, 64), nil
		},
	}

	msg2 := cose.NewSign1Message()
	msg2.Headers.Protected = cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
		cose.HeaderLabelContentType: custodianStatementCTY,
		cose.HeaderLabelKeyID:       kid,
	}
	msg2.Payload = payload
	if err := msg2.Sign(rand.Reader, nil, kmsSigner); err != nil {
		t.Fatal(err)
	}
	if len(gotDigest) != 32 {
		t.Fatalf("KMS digest len %d want 32", len(gotDigest))
	}
	for i := range wantDigest {
		if gotDigest[i] != wantDigest[i] {
			t.Fatalf("digest mismatch at %d: KMS path vs sha256(ToBeSigned)", i)
		}
	}
}
