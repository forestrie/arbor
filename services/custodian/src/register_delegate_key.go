package custodian

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/forestrie/arbor/services/pkgs/delegatekeys"
	"google.golang.org/api/option"
)

// defaultDelegateKeyTTL bounds how long the coordinator keeps a registered
// delegate key (matches the sealer's DELEGATE_KEY_TTL default, plan F2).
const defaultDelegateKeyTTL = 720 * time.Hour

// RegisterDelegateKeyEntry mirrors the coordinator's RegisterDelegateKey JSON
// (canopy types/register-delegate-keys-request.ts).
type RegisterDelegateKeyEntry struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"publicKey"` // base64 canonical COSE_Key CBOR
	Epoch     uint32 `json:"epoch"`
	NotAfter  int64  `json:"notAfter"`
	Voucher   string `json:"voucher"` // base64 untagged COSE_Sign1
}

// RegisterDelegateKeysBody mirrors the coordinator's RegisterDelegateKeysRequest.
type RegisterDelegateKeysBody struct {
	SealerID string                     `json:"sealerId"`
	Keys     []RegisterDelegateKeyEntry `json:"keys"`
}

// buildDelegateKeyRegistration derives the standing public key for
// (sealerID, epoch) from the seed, encodes it as canonical COSE_Key (via the
// shared delegatekeys package, so it matches the sealer's key and the
// coordinator's delegated_pubkey_hash), and signs a voucher over it with
// voucherSign. Pure — no KMS or HTTP — so it is unit-testable.
func buildDelegateKeyRegistration(
	sealerID string,
	epoch uint32,
	notAfter int64,
	seed []byte,
	voucherSign func(DelegateKeyVoucherClaims) ([]byte, error),
) (RegisterDelegateKeysBody, error) {
	priv, err := delegatekeys.DeriveKey(seed, epoch, 0)
	if err != nil {
		return RegisterDelegateKeysBody{}, fmt.Errorf("derive delegate key: %w", err)
	}
	pub := &priv.PublicKey
	coseBytes, err := delegatekeys.CoseKeyBytes(pub)
	if err != nil {
		return RegisterDelegateKeysBody{}, fmt.Errorf("encode delegate key: %w", err)
	}
	voucher, err := voucherSign(DelegateKeyVoucherClaims{SealerID: sealerID, Epoch: epoch, PublicKey: pub})
	if err != nil {
		return RegisterDelegateKeysBody{}, fmt.Errorf("sign voucher: %w", err)
	}
	return RegisterDelegateKeysBody{
		SealerID: sealerID,
		Keys: []RegisterDelegateKeyEntry{{
			Alg:       "ES256",
			PublicKey: base64.StdEncoding.EncodeToString(coseBytes),
			Epoch:     epoch,
			NotAfter:  notAfter,
			Voucher:   base64.StdEncoding.EncodeToString(voucher),
		}},
	}, nil
}

// registerStandingDelegateKey derives the standing key for (sealerID, epoch),
// signs a voucher with the KMS registrar voucher key, and registers both with
// the coordinator. Best-effort: called from the seed handler after the seed is
// derived, and a failure is logged (not returned to the sealer) — the sealer
// re-requests on boot and registration is an idempotent upsert. No-op unless
// the registrar voucher key AND the coordinator are configured.
func (a *API) registerStandingDelegateKey(ctx context.Context, sealerID string, epoch uint32, seed []byte) error {
	if a.cfg.RegistrarVoucherKey == "" || !a.coordinatorConfigured() {
		return nil
	}
	notAfter := time.Now().Add(defaultDelegateKeyTTL).Unix()

	client, err := kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()
	versionName, versionAlg, err := kmsResolveSigningVersion(ctx, client, a.cfg.RegistrarVoucherKey)
	if err != nil {
		return fmt.Errorf("resolve registrar voucher key version: %w", err)
	}

	body, err := buildDelegateKeyRegistration(sealerID, epoch, notAfter, seed,
		func(claims DelegateKeyVoucherClaims) ([]byte, error) {
			return BuildDelegateKeyVoucher(ctx, client, versionName, versionAlg, claims, "registrar")
		})
	if err != nil {
		return err
	}
	return a.postDelegateKeyRegistration(ctx, body)
}

// postDelegateKeyRegistration POSTs the registration to the coordinator's
// delegate-key endpoint with the coordinator bearer token.
func (a *API) postDelegateKeyRegistration(ctx context.Context, body RegisterDelegateKeysBody) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := a.coordinatorBaseURL() + "/api/sealer/delegate-keys"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := a.coordinatorAuthToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("coordinator register returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}
