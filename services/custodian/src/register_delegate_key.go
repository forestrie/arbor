package custodian

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
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

// signRegistrarVoucher signs a delegate-key voucher with the KMS registrar
// voucher key's current signing version. issueDelegateKeyVoucher calls it.
func (a *API) signRegistrarVoucher(ctx context.Context, claims DelegateKeyVoucherClaims) ([]byte, error) {
	client, err := kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()
	versionName, versionAlg, err := kmsResolveSigningVersion(ctx, client, a.cfg.RegistrarVoucherKey)
	if err != nil {
		return nil, fmt.Errorf("resolve registrar voucher key version: %w", err)
	}
	return BuildDelegateKeyVoucher(ctx, client, versionName, versionAlg, claims, "registrar")
}

// postDelegateKeyRegistration POSTs one registration to the coordinator's
// delegate-key endpoint with the coordinator bearer token and reports the
// status and (bounded) body; classifying them is the outbox's job.
func (a *API) postDelegateKeyRegistration(ctx context.Context, body RegisterDelegateKeysBody) registrationOutcome {
	payload, err := json.Marshal(body)
	if err != nil {
		return registrationOutcome{err: err}
	}
	url := a.coordinatorBaseURL() + "/api/sealer/delegate-keys"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return registrationOutcome{err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	if token := a.coordinatorAuthToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return registrationOutcome{err: err}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return registrationOutcome{status: resp.StatusCode, body: b}
}
