package custodian

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"time"
)

// voucherSignTimeout is the custodian's own deadline for signing one voucher
// (a KMS GetPublicKey and AsymmetricSign). The seed handler applies it to a
// context detached from the sealer's request, so a sealer that gives up early
// does not cancel a signature already under way.
const voucherSignTimeout = 10 * time.Second

// voucherSubject is what a voucher attests plus what its issuance log line
// names: the derived standing key for (sealerId, epoch) and the MAC key
// version that just derived it.
type voucherSubject struct {
	sealerID      string
	epoch         uint32
	kmsKeyVersion string
	publicKey     *ecdsa.PublicKey
	pubkeyHash    string // hex(sha256(canonical COSE_Key)), the coordinator's key id
}

// issuedVoucher is a signed voucher and its claim 4 (Unix seconds).
type issuedVoucher struct {
	bytes    []byte
	notAfter int64
}

// issueDelegateKeyVoucher signs a voucher for s whose claim 4 is now plus
// DELEGATE_KEY_VOUCHER_TTL (plan-2609-12 slice 07, ruling 7) and logs the
// issuance at info. That log line is the registrar's audit trail (ruling 4′).
// Callers issue only for an epoch whose MacSign has just succeeded, so a
// disabled KMS version stops getting fresh vouchers.
func (a *API) issueDelegateKeyVoucher(ctx context.Context, s voucherSubject) (issuedVoucher, error) {
	sign := a.signVoucherOverride
	if sign == nil {
		if a.cfg.RegistrarVoucherKey == "" {
			return issuedVoucher{}, errors.New("REGISTRAR_VOUCHER_KEY is not configured")
		}
		sign = a.signRegistrarVoucher
	}
	ttl := a.cfg.delegateKeyVoucherTTL()
	notAfter := a.now().Add(ttl).Unix()
	ctx, cancel := context.WithTimeout(ctx, voucherSignTimeout)
	defer cancel()
	v, err := sign(ctx, DelegateKeyVoucherClaims{
		SealerID:  s.sealerID,
		Epoch:     s.epoch,
		PublicKey: s.publicKey,
		NotAfter:  notAfter,
	})
	if err != nil {
		return issuedVoucher{}, err
	}
	a.Logger.Info("delegate key voucher issued",
		"sealerId", s.sealerID,
		"epoch", s.epoch,
		"kmsKeyVersion", s.kmsKeyVersion,
		"pubkeyHash", s.pubkeyHash,
		"notAfter", notAfter,
		"ttl", ttl.String(),
	)
	return issuedVoucher{bytes: v, notAfter: notAfter}, nil
}
