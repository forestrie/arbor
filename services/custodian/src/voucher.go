package custodian

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/forestrie/arbor/services/pkgs/delegatekeys"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// A delegate-key voucher is the custodian's attestation that a standing
// delegate public key was derived from the KMS seed for a given (sealerId,
// epoch) — FOR-390 phase G / ADR-0050 §"Trust model and genesis topology".
// The coordinator advertises it with the standing entry; the kit verifies it
// against the pinned registrar key before signAdvanceDelegation binds the key,
// so a compromised coordinator cannot induce a root holder to delegate to a
// key the sealer does not control.
//
// It is signed by a dedicated registrar voucher key (REGISTRAR_VOUCHER_KEY),
// distinct from the KMS-MAC seed key (which cannot make public-verifiable
// signatures) and from the per-log custody keys.
const delegateKeyVoucherCTY = "application/forestrie.delegate-key-voucher+cbor"

// voucherClaimsWire is the canonical int-keyed CBOR payload of a voucher.
// The delegate key is the shared canonical COSE_Key bytes (delegatekeys.
// CoseKeyBytes), so it is byte-identical to the coordinator's
// delegated_pubkey_hash preimage. Verification decodes and field-compares
// (no re-canonicalisation), so the TS kit can mirror it without a cross-impl
// canonical-CBOR equivalence requirement on the voucher envelope.
type voucherClaimsWire struct {
	SealerID string `cbor:"1,keyasint"`
	Epoch    uint32 `cbor:"2,keyasint"`
	Key      []byte `cbor:"3,keyasint"`
}

// DelegateKeyVoucherClaims is the attested tuple in decoded form.
type DelegateKeyVoucherClaims struct {
	SealerID  string
	Epoch     uint32
	PublicKey *ecdsa.PublicKey
}

var canonicalVoucherCBOR cbor.EncMode

func init() {
	em, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	if err != nil {
		panic(fmt.Errorf("custodian: build voucher CBOR EncMode: %w", err))
	}
	canonicalVoucherCBOR = em
}

// encodeVoucherClaims canonically encodes the claims as the COSE_Sign1 payload.
func encodeVoucherClaims(c DelegateKeyVoucherClaims) ([]byte, error) {
	if c.SealerID == "" {
		return nil, fmt.Errorf("voucher: empty sealerId")
	}
	if c.Epoch == 0 {
		return nil, fmt.Errorf("voucher: epoch must be >= 1")
	}
	keyBytes, err := delegatekeys.CoseKeyBytes(c.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("voucher: encode delegate key: %w", err)
	}
	return canonicalVoucherCBOR.Marshal(voucherClaimsWire{
		SealerID: c.SealerID,
		Epoch:    c.Epoch,
		Key:      keyBytes,
	})
}

// BuildDelegateKeyVoucherWithSigner assembles an untagged COSE_Sign1 voucher
// over the canonical claims, signed by `signer`. Split from the KMS wiring so
// it is unit-testable with a local key. The embedded-claims profile (payload =
// claims, not a digest) keeps verification a signature check plus a
// field-compare.
func BuildDelegateKeyVoucherWithSigner(claims DelegateKeyVoucherClaims, kid []byte, signer cose.Signer) ([]byte, error) {
	payload, err := encodeVoucherClaims(claims)
	if err != nil {
		return nil, err
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected = cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm:   signer.Algorithm(),
		cose.HeaderLabelContentType: delegateKeyVoucherCTY,
		cose.HeaderLabelKeyID:       kid,
	}
	msg.Payload = payload
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("voucher cose sign1: %w", err)
	}
	u := cose.UntaggedSign1Message(*msg)
	return u.MarshalCBOR()
}

// VerifyDelegateKeyVoucher verifies the voucher signature against pinnedKey and
// confirms the decoded claims equal `want`. Mirrored by the TS kit (phase I);
// also usable coordinator-side for defense-in-depth at registration ingest.
func VerifyDelegateKeyVoucher(voucherBytes []byte, pinnedKey *ecdsa.PublicKey, want DelegateKeyVoucherClaims) error {
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, pinnedKey)
	if err != nil {
		return fmt.Errorf("voucher: build verifier: %w", err)
	}
	var u cose.UntaggedSign1Message
	if err := u.UnmarshalCBOR(voucherBytes); err != nil {
		return fmt.Errorf("voucher: decode: %w", err)
	}
	msg := cose.Sign1Message(u)
	if err := msg.Verify(nil, verifier); err != nil {
		return fmt.Errorf("voucher: signature: %w", err)
	}
	var got voucherClaimsWire
	if err := cbor.Unmarshal(msg.Payload, &got); err != nil {
		return fmt.Errorf("voucher: decode claims: %w", err)
	}
	wantKey, err := delegatekeys.CoseKeyBytes(want.PublicKey)
	if err != nil {
		return err
	}
	if got.SealerID != want.SealerID || got.Epoch != want.Epoch || !bytes.Equal(got.Key, wantKey) {
		return fmt.Errorf("voucher: claims mismatch (sealerId/epoch/key)")
	}
	return nil
}

// BuildDelegateKeyVoucher signs a voucher with the KMS registrar voucher key
// (versionName). It mirrors BuildCustodianCOSESign1's KMS wiring; the KMS path
// is exercised by the live registration flow (phase G3), not unit tests.
func BuildDelegateKeyVoucher(
	ctx context.Context,
	client *kms.KeyManagementClient,
	versionName string,
	versionAlg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm,
	claims DelegateKeyVoucherClaims,
	signKeyID string,
) ([]byte, error) {
	alg, err := coseAlgFromKMS(versionAlg)
	if err != nil {
		return nil, err
	}
	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
	if err != nil {
		return nil, fmt.Errorf("voucher: get registrar public key: %w", err)
	}
	pub, err := parseECDSAPublicKeyFromPEM(pubResp.GetPem())
	if err != nil {
		return nil, err
	}
	kid, err := KidFromECDSAPublicKey(pub)
	if err != nil {
		return nil, err
	}
	const coordWidth = 32
	signer := &kmsCOSESigner{
		alg:       alg,
		ctx:       ctx,
		signKeyID: signKeyID,
		sign: func(c context.Context, digest []byte) ([]byte, error) {
			der, err := kmsAsymmetricSignSHA256(c, client, versionName, digest)
			if err != nil {
				return nil, err
			}
			return ecdsaDERSignatureToIEEE1363(der, coordWidth)
		},
	}
	return BuildDelegateKeyVoucherWithSigner(claims, kid, signer)
}
