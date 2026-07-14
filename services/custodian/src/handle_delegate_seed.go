package custodian

import (
	"context"
	"fmt"
	"io"
	"net/http"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/fxamacker/cbor/v2"
	"google.golang.org/api/option"
)

// delegateSeedPrefix is the fixed derivation-input prefix (ADR-0050 /
// plan-2607-20 phase A). It is applied server-side so this endpoint is a
// narrow seed-derivation surface, never a general MAC oracle: callers choose
// only (sealerId, epoch) and sealerId must be allowlisted.
const delegateSeedPrefix = "forestrie/sealer-delegate-seed/v1"

// DelegateSeedRequest is the CBOR body for POST /api/delegate-seed.
type DelegateSeedRequest struct {
	SealerID string `cbor:"sealerId"`
	Epoch    uint32 `cbor:"epoch"`
}

// DelegateSeedResponse carries the deterministically derived seed. MacSign
// with HMAC-SHA256 is deterministic per key version: the same
// (sealerId, epoch) always yields the same seed, so sealer delegate keys —
// and every advance delegation certificate bound to them — survive process
// restarts with no private material at rest anywhere (ADR-0050 Q3).
type DelegateSeedResponse struct {
	Seed          []byte `cbor:"seed"`
	KMSKeyVersion string `cbor:"kmsKeyVersion"`
}

// handleDelegateSeed derives the sealer delegate-key seed inside KMS.
//
// POST /api/delegate-seed (APP_TOKEN, CBOR): the seed is the HMAC-SHA256 MAC
// of "<prefix>/<sealerId>/<epoch>" under the dedicated DELEGATE_SEED_MAC_KEY
// (Cloud KMS purpose MAC). Every derivation is a KMS audit-log event.
func (a *API) handleDelegateSeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if !a.RequireNormalApp(w, r) {
		return
	}
	if a.cfg.DelegateSeedMacKey == "" {
		a.writeProblem(w, r, http.StatusNotImplemented, "about:blank", "not configured",
			"DELEGATE_SEED_MAC_KEY is not configured on this custodian")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "read body")
		return
	}
	var req DelegateSeedRequest
	if err := cbor.Unmarshal(body, &req); err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "body must be CBOR")
		return
	}
	if req.SealerID == "" {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "sealerId is required")
		return
	}
	if req.Epoch == 0 {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "epoch must be >= 1")
		return
	}
	if !a.cfg.delegateSeedSealerAllowed(req.SealerID) {
		a.writeProblem(w, r, http.StatusForbidden, "about:blank", "forbidden",
			fmt.Sprintf("sealerId %q is not in DELEGATE_SEED_SEALERS", req.SealerID))
		return
	}

	data := []byte(fmt.Sprintf("%s/%s/%d", delegateSeedPrefix, req.SealerID, req.Epoch))

	macSign := a.macSignOverride
	if macSign == nil {
		macSign = func(ctx context.Context, keyName string, data []byte) ([]byte, string, error) {
			client, err := kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
			if err != nil {
				return nil, "", fmt.Errorf("kms client: %w", err)
			}
			defer client.Close()
			version, err := kmsLatestEnabledMacVersion(ctx, client, keyName)
			if err != nil {
				return nil, "", err
			}
			resp, err := client.MacSign(ctx, &kmspb.MacSignRequest{Name: version, Data: data})
			if err != nil {
				return nil, "", fmt.Errorf("kms MacSign: %w", err)
			}
			return resp.Mac, resp.Name, nil
		}
	}

	seed, keyVersion, err := macSign(r.Context(), a.cfg.DelegateSeedMacKey, data)
	if err != nil {
		a.Logger.Error("delegate seed derivation failed", "sealerId", req.SealerID, "epoch", req.Epoch, "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "kms error", "seed derivation failed")
		return
	}

	a.Logger.Info("delegate seed derived",
		"sealerId", req.SealerID,
		"epoch", req.Epoch,
		"kmsKeyVersion", keyVersion,
	)

	// Register the standing delegate key + custodian voucher with the
	// coordinator (FOR-390 phase G3). Best-effort: a failure must not fail the
	// seed response (the sealer needs the seed to boot); the sealer re-requests
	// on boot and registration is idempotent.
	if err := a.registerStandingDelegateKey(r.Context(), req.SealerID, req.Epoch, seed); err != nil {
		a.Logger.Warn("delegate key registration failed (non-fatal)",
			"sealerId", req.SealerID, "epoch", req.Epoch, "error", err)
	}

	a.writeCBOR(w, http.StatusOK, DelegateSeedResponse{Seed: seed, KMSKeyVersion: keyVersion})
}

// kmsLatestEnabledMacVersion resolves the newest ENABLED version of a MAC
// key. MacSign requires a version resource name (unlike AsymmetricSign the
// primary-version shortcut does not apply to MAC keys via the cryptoKey
// name in all API surfaces, so resolve explicitly).
func kmsLatestEnabledMacVersion(ctx context.Context, client *kms.KeyManagementClient, cryptoKeyName string) (string, error) {
	it := client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
		Parent: cryptoKeyName,
		Filter: "state = ENABLED",
	})
	latest := ""
	for {
		v, err := it.Next()
		if err != nil {
			break
		}
		if v.Name > latest {
			latest = v.Name
		}
	}
	if latest == "" {
		return "", fmt.Errorf("no enabled versions for MAC key %s", cryptoKeyName)
	}
	return latest, nil
}
