package custodian

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/fxamacker/cbor/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// delegateSeedPrefix is the fixed derivation-input prefix (ADR-0050 /
// plan-2607-20 phase A). It is applied server-side so this endpoint is a
// narrow seed-derivation surface, never a general MAC oracle: callers choose
// only (sealerId, epoch) and sealerId must be allowlisted.
const delegateSeedPrefix = "forestrie/sealer-delegate-seed/v1"

// errDelegateSeedEpochRetired reports that the MAC key version named by the
// requested epoch is not usable: it does not exist (never created, or
// destroyed) or is not ENABLED (disabled, or scheduled for destruction). The
// handler maps it to 409 so the sealer can tell "this epoch is retired" from
// "KMS is unavailable" (502) and stop retrying the former.
var errDelegateSeedEpochRetired = errors.New("delegate seed epoch retired: no enabled MAC key version")

// delegateSeedMacKeyVersion names the CryptoKeyVersion that derives seeds for
// an epoch. The epoch IS the MAC key version number (plan-2609-11): epoch e is
// always signed under <DELEGATE_SEED_MAC_KEY>/cryptoKeyVersions/<e>. That makes
// the version a fixed function of the epoch rather than of listing state at
// request time, so a key-version rotation is an epoch bump and the sealer's
// N/N-1 overlap covers it: epoch N-1 keeps deriving under version N-1 for as
// long as that version stays enabled.
func delegateSeedMacKeyVersion(cryptoKeyName string, epoch uint32) string {
	return cryptoKeyName + "/cryptoKeyVersions/" + strconv.FormatUint(uint64(epoch), 10)
}

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
	if strings.Contains(a.cfg.DelegateSeedMacKey, "/cryptoKeyVersions/") {
		// The epoch selects the version; a pinned version would silently
		// override every epoch with one key and defeat the N/N-1 overlap.
		a.writeProblem(w, r, http.StatusNotImplemented, "about:blank", "misconfigured",
			"DELEGATE_SEED_MAC_KEY must name a CryptoKey, not a CryptoKeyVersion")
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
	versionName := delegateSeedMacKeyVersion(a.cfg.DelegateSeedMacKey, req.Epoch)

	macSign := a.macSignOverride
	if macSign == nil {
		macSign = kmsMacSignVersion
	}

	seed, keyVersion, err := macSign(r.Context(), versionName, data)
	if err != nil {
		if errors.Is(err, errDelegateSeedEpochRetired) {
			a.Logger.Warn("delegate seed epoch retired", "sealerId", req.SealerID, "epoch", req.Epoch, "kmsKeyVersion", versionName, "error", err)
			a.writeProblem(w, r, http.StatusConflict, "about:blank", "epoch retired",
				fmt.Sprintf("no enabled MAC key version for epoch %d", req.Epoch))
			return
		}
		a.Logger.Error("delegate seed derivation failed", "sealerId", req.SealerID, "epoch", req.Epoch, "kmsKeyVersion", versionName, "error", err)
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

// kmsMacSignVersion computes the HMAC of data under one explicit
// CryptoKeyVersion. KMS refuses a version that is not ENABLED (FailedPrecondition)
// or does not exist (NotFound); both mean the epoch is retired.
func kmsMacSignVersion(ctx context.Context, versionName string, data []byte) ([]byte, string, error) {
	client, err := kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return nil, "", fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()
	resp, err := client.MacSign(ctx, &kmspb.MacSignRequest{Name: versionName, Data: data})
	if err != nil {
		if kmsErrIsRetiredVersion(err) {
			return nil, "", fmt.Errorf("%w: %s: %v", errDelegateSeedEpochRetired, versionName, err)
		}
		return nil, "", fmt.Errorf("kms MacSign: %w", err)
	}
	return resp.Mac, resp.Name, nil
}

// kmsErrIsRetiredVersion reports whether a MacSign error means the named
// version cannot be used at all (as opposed to a transient or auth failure).
func kmsErrIsRetiredVersion(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	case codes.NotFound, codes.FailedPrecondition:
		return true
	}
	return false
}
