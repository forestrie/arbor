package custodian

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"time"

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

// voucherClaimsWire is the canonical int-keyed CBOR payload of a voucher:
// {1: sealerId, 2: epoch, 3: delegateKeyCoseCbor, 4: notAfter}. Claim 4 is
// Unix seconds (plan-2609-12 slice 07, ruling 7); vouchers issued before it
// lack the claim, which decodes as 0.
// The delegate key is the shared canonical COSE_Key bytes (delegatekeys.
// CoseKeyBytes), so it is byte-identical to the coordinator's
// delegated_pubkey_hash preimage. Verification decodes and field-compares
// (no re-canonicalisation), so the TS kit can mirror it without a cross-impl
// canonical-CBOR equivalence requirement on the voucher envelope.
type voucherClaimsWire struct {
	SealerID string `cbor:"1,keyasint"`
	Epoch    uint32 `cbor:"2,keyasint"`
	Key      []byte `cbor:"3,keyasint"`
	NotAfter uint64 `cbor:"4,keyasint,omitempty"`
}

// DelegateKeyVoucherClaims is the attested tuple in decoded form.
type DelegateKeyVoucherClaims struct {
	SealerID  string
	Epoch     uint32
	PublicKey *ecdsa.PublicKey
	// NotAfter is claim 4, the voucher's expiry in Unix seconds. 0 means
	// absent: the builder refuses it, and a verifier given it as `want`
	// does not compare it.
	NotAfter int64
}

// VerifyDelegateKeyVoucherOptions tunes VerifyDelegateKeyVoucher.
type VerifyDelegateKeyVoucherOptions struct {
	// RequireNotAfter refuses a voucher without claim 4. Off, such a voucher
	// (issued before slice 07) still verifies until slice 08's cutover.
	RequireNotAfter bool
}

var (
	// ErrVoucherNotAfterMissing: claim 4 is absent and was required. The text
	// matches the TypeScript verifier's reason, not_after_missing.
	ErrVoucherNotAfterMissing = errors.New("voucher: not_after_missing")
	// ErrVoucherExpired: claim 4 is not after now (TypeScript reason expired).
	ErrVoucherExpired = errors.New("voucher: expired")
)

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
	if c.NotAfter <= 0 {
		// Every voucher this custodian issues expires (ruling 7).
		return nil, fmt.Errorf("voucher: notAfter (claim 4) is required")
	}
	keyBytes, err := delegatekeys.CoseKeyBytes(c.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("voucher: encode delegate key: %w", err)
	}
	return canonicalVoucherCBOR.Marshal(voucherClaimsWire{
		SealerID: c.SealerID,
		Epoch:    c.Epoch,
		Key:      keyBytes,
		NotAfter: uint64(c.NotAfter),
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

// VerifyDelegateKeyVoucher verifies the voucher signature against pinnedKey,
// confirms the decoded claims equal `want` (NotAfter only when want sets it)
// and returns claim 4 (0 when absent). Claim 4, when present, must be after
// now (ErrVoucherExpired); opts.RequireNotAfter refuses its absence
// (ErrVoucherNotAfterMissing). Mirrors canopy @forestrie/encoding
// verifyDelegateKeyVoucher; the protocol vector delegate-key-voucher.json
// pins the two together.
func VerifyDelegateKeyVoucher(
	voucherBytes []byte,
	pinnedKey *ecdsa.PublicKey,
	want DelegateKeyVoucherClaims,
	now time.Time,
	opts VerifyDelegateKeyVoucherOptions,
) (int64, error) {
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, pinnedKey)
	if err != nil {
		return 0, fmt.Errorf("voucher: build verifier: %w", err)
	}
	var u cose.UntaggedSign1Message
	if err := u.UnmarshalCBOR(voucherBytes); err != nil {
		return 0, fmt.Errorf("voucher: decode: %w", err)
	}
	msg := cose.Sign1Message(u)
	if err := msg.Verify(nil, verifier); err != nil {
		return 0, fmt.Errorf("voucher: signature: %w", err)
	}
	var got voucherClaimsWire
	if err := cbor.Unmarshal(msg.Payload, &got); err != nil {
		return 0, fmt.Errorf("voucher: decode claims: %w", err)
	}
	wantKey, err := delegatekeys.CoseKeyBytes(want.PublicKey)
	if err != nil {
		return 0, err
	}
	if got.SealerID != want.SealerID || got.Epoch != want.Epoch || !bytes.Equal(got.Key, wantKey) {
		return 0, fmt.Errorf("voucher: claims mismatch (sealerId/epoch/key)")
	}
	if got.NotAfter > math.MaxInt64 {
		return 0, fmt.Errorf("voucher: notAfter %d out of range", got.NotAfter)
	}
	notAfter := int64(got.NotAfter)
	if want.NotAfter != 0 && notAfter != want.NotAfter {
		return 0, fmt.Errorf("voucher: claims mismatch (notAfter %d, want %d)", notAfter, want.NotAfter)
	}
	if notAfter == 0 {
		if opts.RequireNotAfter {
			return 0, ErrVoucherNotAfterMissing
		}
		return 0, nil
	}
	if now.Unix() >= notAfter {
		return notAfter, fmt.Errorf("%w: notAfter %d, now %d", ErrVoucherExpired, notAfter, now.Unix())
	}
	return notAfter, nil
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
