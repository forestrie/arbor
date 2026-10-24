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
	"github.com/forestrie/arbor/services/pkgs/delegatekeys"
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

// errDelegateSeedVersionNotFound reports KMS NotFound for the epoch's
// CryptoKeyVersion. KMS answers NotFound for a missing key as well as a missing
// version, so the handler checks the parent key before answering: key present
// means the epoch is retired (409), key missing means misconfiguration (501).
var errDelegateSeedVersionNotFound = errors.New("delegate seed MAC key version not found")

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

// Contract versions of POST /api/delegate-seed, per the internal-API
// versioning convention (plan-2609-12 slice 02): absent means 1, per
// endpoint, the client refuses a response below its minimum, and the server
// echoes the version served and answers 400 above the newest it serves.
//
//   - 2: the epoch IS the MAC key version number (plan-2609-11); a sealer
//     that requires 2 refuses a response from a custodian that predates it.
//     Requests at 1, 2 or absent are all served as 2.
//   - 3: the response also carries the registrar voucher for the derived
//     key and its claim 4, voucherNotAfter (plan-2609-12 slice 07). A
//     response without a voucher means signing failed; the sealer installs
//     the key and asks again.
const (
	delegateSeedAPIVersionEpochIsVersion = 2
	delegateSeedAPIVersionVoucher        = 3
	delegateSeedAPIVersionMax            = delegateSeedAPIVersionVoucher
)

// DelegateSeedRequest is the CBOR body for POST /api/delegate-seed.
type DelegateSeedRequest struct {
	SealerID string `cbor:"sealerId"`
	Epoch    uint32 `cbor:"epoch"`
	// APIVersion is the contract version the sealer speaks; absent means 1.
	APIVersion uint32 `cbor:"apiVersion,omitempty"`
}

// DelegateSeedResponse carries the deterministically derived seed. MacSign
// with HMAC-SHA256 is deterministic per key version: the same
// (sealerId, epoch) always yields the same seed, so sealer delegate keys —
// and every advance delegation certificate bound to them — survive process
// restarts with no private material at rest anywhere (ADR-0050 Q3).
//
// Wire shape (CBOR map, text keys): {seed: bstr, kmsKeyVersion: tstr,
// apiVersion: uint} at version 2, plus {voucher: bstr, voucherNotAfter: uint}
// at version 3 when a voucher was signed. The sealer's decoder in arbor
// services/sealer mirrors it.
type DelegateSeedResponse struct {
	Seed          []byte `cbor:"seed"`
	KMSKeyVersion string `cbor:"kmsKeyVersion"`
	// APIVersion is the version served: 2 for a request at 2 or below, else 3.
	APIVersion uint32 `cbor:"apiVersion"`
	// Voucher is the registrar voucher (untagged COSE_Sign1, ES256) for the
	// standing key derived from Seed; version 3 only, absent when signing
	// failed.
	Voucher []byte `cbor:"voucher,omitempty"`
	// VoucherNotAfter is the voucher's claim 4, Unix seconds; set with Voucher.
	VoucherNotAfter int64 `cbor:"voucherNotAfter,omitempty"`
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
	if !a.delegateSeedVerified.Load() {
		// The boot probe has not yet confirmed the key is an HMAC_SHA256 MAC
		// key (plan-2609-12 ruling 2); it retries on a timer.
		a.writeProblem(w, r, http.StatusNotImplemented, "about:blank", "misconfigured",
			"DELEGATE_SEED_MAC_KEY has not been verified as an HMAC_SHA256 MAC key")
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
	if req.APIVersion > delegateSeedAPIVersionMax {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "unsupported apiVersion",
			fmt.Sprintf("apiVersion %d is not supported; this custodian serves 1 to %d", req.APIVersion, delegateSeedAPIVersionMax))
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
	if errors.Is(err, errDelegateSeedVersionNotFound) {
		err = a.disambiguateVersionNotFound(r.Context(), err)
		if errors.Is(err, errDelegateSeedKeyMisconfigured) {
			a.Logger.Error("delegate seed MAC key missing", "key", a.cfg.DelegateSeedMacKey,
				"sealerId", req.SealerID, "epoch", req.Epoch, "error", err)
			a.writeProblem(w, r, http.StatusNotImplemented, "about:blank", "misconfigured",
				"DELEGATE_SEED_MAC_KEY does not exist")
			return
		}
	}
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

	resp := DelegateSeedResponse{Seed: seed, KMSKeyVersion: keyVersion, APIVersion: delegateSeedAPIVersionEpochIsVersion}
	var issued *issuedVoucher
	if req.APIVersion >= delegateSeedAPIVersionVoucher {
		resp.APIVersion = delegateSeedAPIVersionVoucher
		// Signed only after this epoch's MacSign succeeded, on the
		// custodian's own deadline rather than the sealer's request context.
		v, err := a.voucherForSeed(context.WithoutCancel(r.Context()), req.SealerID, req.Epoch, keyVersion, seed)
		if err != nil {
			a.Logger.Warn("delegate key voucher not issued; answering the seed without it",
				"sealerId", req.SealerID, "epoch", req.Epoch, "kmsKeyVersion", keyVersion, "error", err)
		} else {
			resp.Voucher, resp.VoucherNotAfter = v.bytes, v.notAfter
			issued = &v
		}
	}

	// Answer first (plan-2609-12 ruling 1): the sealer needs only the seed
	// (and, at version 3, the voucher). Registering the standing key with the
	// coordinator is the outbox's job, off this request's context and
	// deadline, with the same voucher when there is one.
	a.writeCBOR(w, http.StatusOK, resp)

	if a.registrations != nil {
		if err := a.registrations.enqueue(req.SealerID, req.Epoch, keyVersion, seed, issued); err != nil {
			a.Logger.Error("delegate key registration not queued",
				"sealerId", req.SealerID, "epoch", req.Epoch, "kmsKeyVersion", keyVersion, "error", err)
		}
	}
}

// voucherForSeed derives the standing public key for (sealerID, epoch) from
// seed, exactly as the sealer does, and issues its voucher.
func (a *API) voucherForSeed(ctx context.Context, sealerID string, epoch uint32, kmsKeyVersion string, seed []byte) (issuedVoucher, error) {
	priv, err := delegatekeys.DeriveKey(seed, epoch, 0)
	if err != nil {
		return issuedVoucher{}, fmt.Errorf("derive delegate key: %w", err)
	}
	pubkeyHash, err := delegatekeys.PubkeyHashHex(&priv.PublicKey)
	if err != nil {
		return issuedVoucher{}, fmt.Errorf("hash delegate key: %w", err)
	}
	return a.issueDelegateKeyVoucher(ctx, voucherSubject{
		sealerID:      sealerID,
		epoch:         epoch,
		kmsKeyVersion: kmsKeyVersion,
		publicKey:     &priv.PublicKey,
		pubkeyHash:    pubkeyHash,
	})
}

// disambiguateVersionNotFound resolves a MacSign NotFound by checking the
// parent CryptoKey. Parent missing: errDelegateSeedKeyMisconfigured. Parent
// present: errDelegateSeedEpochRetired, so 409 means exactly "the key exists
// and version e is unusable". Any other failure of the check is returned
// as-is (502).
func (a *API) disambiguateVersionNotFound(ctx context.Context, notFound error) error {
	get := a.getDelegateSeedKeyOverride
	if get == nil {
		get = kmsGetDelegateSeedKey
	}
	if _, err := get(ctx, a.cfg.DelegateSeedMacKey); err != nil {
		if errors.Is(err, errDelegateSeedKeyMisconfigured) {
			return err
		}
		return fmt.Errorf("check parent key after %v: %w", notFound, err)
	}
	return fmt.Errorf("%w: %v", errDelegateSeedEpochRetired, notFound)
}

// kmsMacSignVersion computes the HMAC of data under one explicit
// CryptoKeyVersion. KMS refuses a version that is not ENABLED
// (FailedPrecondition: the epoch is retired) or does not exist (NotFound:
// ambiguous until the parent key is checked, see disambiguateVersionNotFound).
func kmsMacSignVersion(ctx context.Context, versionName string, data []byte) ([]byte, string, error) {
	client, err := kms.NewKeyManagementClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return nil, "", fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()
	resp, err := client.MacSign(ctx, &kmspb.MacSignRequest{Name: versionName, Data: data})
	if err != nil {
		return nil, "", kmsMacSignError(versionName, err)
	}
	return resp.Mac, resp.Name, nil
}

// kmsMacSignError classifies a MacSign failure for one version: NotFound is
// errDelegateSeedVersionNotFound (ambiguous between key and version),
// FailedPrecondition (version not ENABLED) is errDelegateSeedEpochRetired, and
// anything else is a KMS failure the handler answers with 502.
func kmsMacSignError(versionName string, err error) error {
	switch status.Code(err) {
	case codes.NotFound:
		return fmt.Errorf("%w: %s: %v", errDelegateSeedVersionNotFound, versionName, err)
	case codes.FailedPrecondition:
		return fmt.Errorf("%w: %s: %v", errDelegateSeedEpochRetired, versionName, err)
	}
	return fmt.Errorf("kms MacSign: %w", err)
}
