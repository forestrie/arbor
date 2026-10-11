package custodian

import (
	"context"
	"errors"
	"fmt"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Boot probe retry interval bounds (plan-2609-12 slice 03, ruling 2). The
// probe never gives up: the custodian also countersigns checkpoints, so it
// must not exit because the delegate-seed MAC key is unusable.
const (
	delegateSeedProbeBackoffBase = 2 * time.Second
	delegateSeedProbeBackoffMax  = 5 * time.Minute
	delegateSeedProbeTimeout     = 30 * time.Second
)

// errDelegateSeedKeyMisconfigured reports that DELEGATE_SEED_MAC_KEY names a
// key that is missing or is not an HMAC_SHA256 MAC key. Distinct from a
// transient KMS failure only for logging: both keep the probe retrying.
var errDelegateSeedKeyMisconfigured = errors.New("delegate seed MAC key misconfigured")

// delegateSeedKeyInfo is what the probe learns about DELEGATE_SEED_MAC_KEY.
type delegateSeedKeyInfo struct {
	Purpose         kmspb.CryptoKey_CryptoKeyPurpose
	Algorithm       kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	EnabledVersions []string
}

// kmsGetDelegateSeedKey reads the CryptoKey and its ENABLED versions. A
// NotFound on the key itself is wrapped in errDelegateSeedKeyMisconfigured.
func kmsGetDelegateSeedKey(ctx context.Context, keyName string) (delegateSeedKeyInfo, error) {
	client, err := kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return delegateSeedKeyInfo{}, fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()
	ck, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyName})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return delegateSeedKeyInfo{}, fmt.Errorf("%w: %s does not exist: %v", errDelegateSeedKeyMisconfigured, keyName, err)
		}
		return delegateSeedKeyInfo{}, fmt.Errorf("get crypto key: %w", err)
	}
	info := delegateSeedKeyInfo{Purpose: ck.Purpose}
	if ck.VersionTemplate != nil {
		info.Algorithm = ck.VersionTemplate.Algorithm
	}
	it := client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
		Parent: keyName,
		Filter: "state=ENABLED",
	})
	for {
		ver, e := it.Next()
		if e == iterator.Done {
			break
		}
		if e != nil {
			return delegateSeedKeyInfo{}, fmt.Errorf("list crypto key versions: %w", e)
		}
		info.EnabledVersions = append(info.EnabledVersions, ver.Name)
	}
	return info, nil
}

// probeDelegateSeedKey checks DELEGATE_SEED_MAC_KEY once: the key exists, has
// purpose MAC and algorithm HMAC_SHA256. On success it sets the verified flag
// and logs the resolved name and enabled versions.
func (a *API) probeDelegateSeedKey(ctx context.Context) error {
	get := a.getDelegateSeedKeyOverride
	if get == nil {
		get = kmsGetDelegateSeedKey
	}
	keyName := a.cfg.DelegateSeedMacKey
	info, err := get(ctx, keyName)
	if err != nil {
		return err
	}
	if info.Purpose != kmspb.CryptoKey_MAC {
		return fmt.Errorf("%w: %s has purpose %s, want MAC", errDelegateSeedKeyMisconfigured, keyName, info.Purpose)
	}
	if info.Algorithm != kmspb.CryptoKeyVersion_HMAC_SHA256 {
		return fmt.Errorf("%w: %s has algorithm %s, want HMAC_SHA256", errDelegateSeedKeyMisconfigured, keyName, info.Algorithm)
	}
	a.delegateSeedVerified.Store(true)
	a.Logger.Info("delegate seed MAC key verified",
		"key", keyName, "enabledVersions", info.EnabledVersions)
	return nil
}

// runDelegateSeedProbe probes until the MAC key verifies or ctx ends, backing
// off between attempts. A misconfiguration logs at error, anything else at
// warn; neither stops the custodian, so a transient KMS outage at boot heals
// and a fixed config is picked up without a restart.
func (a *API) runDelegateSeedProbe(ctx context.Context) {
	backoff := delegateSeedProbeBackoffBase
	for {
		attemptCtx, cancel := context.WithTimeout(ctx, delegateSeedProbeTimeout)
		err := a.probeDelegateSeedKey(attemptCtx)
		cancel()
		if err == nil {
			return
		}
		if errors.Is(err, errDelegateSeedKeyMisconfigured) {
			a.Logger.Error("delegate seed MAC key probe failed; seed requests answer 501",
				"key", a.cfg.DelegateSeedMacKey, "error", err, "retryIn", backoff.String())
		} else {
			a.Logger.Warn("delegate seed MAC key probe failed; seed requests answer 501",
				"key", a.cfg.DelegateSeedMacKey, "error", err, "retryIn", backoff.String())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, delegateSeedProbeBackoffMax)
	}
}
