package sealer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// errDelegateSeedEpochRetired reports the custodian's 409: the KMS MAC key
// version named by the epoch is disabled or gone, so the epoch can never be
// derived again (plan-2609-11: the epoch IS the key version number). A
// retired N-1 loads epoch N alone; a retired N holds readiness and retries,
// like any other boot fault (devdocs plan-2609-12 slice 05 change 7).
var errDelegateSeedEpochRetired = errors.New("delegate seed epoch retired")

// custodianSeedProvider derives the delegate-key seed via the custodian's
// POST /api/delegate-seed (KMS-MAC; ADR-0050 phase A). The seed is never at
// rest: it is derived at boot and again on each voucher refresh.
type custodianSeedProvider struct {
	baseURL    string
	token      string
	sealerID   string
	httpClient *HTTPClient
	logger     *slog.Logger // optional; logs the KMS key version each seed derived under
}

// delegateSeedAPIVersion is the contract version of POST /api/delegate-seed
// this sealer requires. Version 2: the epoch IS the MAC key version number
// (plan-2609-11). Version 3: each answer also carries the registrar voucher
// for the derived key and the voucher's notAfter, which the sealer presents
// when it asserts its registration (devdocs plan-2609-12 slice 07). A
// custodian below 3 is refused, so a sealer that must assert never runs
// without vouchers. Internal-API versioning convention: plan-2609-12 slice 02.
const delegateSeedAPIVersion = 3

type delegateSeedRequest struct {
	SealerID   string `cbor:"sealerId"`
	Epoch      uint32 `cbor:"epoch"`
	APIVersion uint32 `cbor:"apiVersion,omitempty"`
}

// delegateSeedResponse is the custodian's answer (arbor
// services/custodian/src/handle_delegate_seed.go, DelegateSeedResponse).
type delegateSeedResponse struct {
	Seed          []byte `cbor:"seed"`
	KMSKeyVersion string `cbor:"kmsKeyVersion"`
	APIVersion    uint32 `cbor:"apiVersion"` // absent means 1
	// Voucher is absent when the custodian failed to sign one; the sealer
	// installs the key and asks again.
	Voucher         []byte `cbor:"voucher,omitempty"`
	VoucherNotAfter uint64 `cbor:"voucherNotAfter,omitempty"` // Unix seconds, equal to claim 4
}

// Seed requests the seed and voucher for epoch.
func (p custodianSeedProvider) Seed(ctx context.Context, epoch uint32) (DelegateSeed, error) {
	body, err := cbor.Marshal(delegateSeedRequest{SealerID: p.sealerID, Epoch: epoch, APIVersion: delegateSeedAPIVersion})
	if err != nil {
		return DelegateSeed{}, err
	}
	req, err := http.NewRequest(http.MethodPost, p.baseURL+"/api/delegate-seed", bytes.NewReader(body))
	if err != nil {
		return DelegateSeed{}, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("Accept", "application/cbor")

	resp, err := p.httpClient.Do(ctx, req)
	if err != nil {
		return DelegateSeed{}, fmt.Errorf("delegate-seed request: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode == http.StatusConflict {
		return DelegateSeed{}, fmt.Errorf("%w: epoch %d (custodian status=409)", errDelegateSeedEpochRetired, epoch)
	}
	if resp.StatusCode != http.StatusOK {
		// The problem says which hold this is, e.g. 501 while the custodian
		// has not verified its MAC key (plan-2609-12 ruling 2).
		var problem struct {
			Title  string `cbor:"title"`
			Detail string `cbor:"detail"`
		}
		_ = cbor.Unmarshal(respBytes, &problem)
		return DelegateSeed{}, fmt.Errorf("delegate-seed status=%d title=%q detail=%q", resp.StatusCode, problem.Title, problem.Detail)
	}
	var out delegateSeedResponse
	if err := cbor.Unmarshal(respBytes, &out); err != nil {
		return DelegateSeed{}, fmt.Errorf("decode delegate-seed response: %w", err)
	}
	if len(out.Seed) == 0 {
		return DelegateSeed{}, fmt.Errorf("delegate-seed response missing seed")
	}
	if out.APIVersion < delegateSeedAPIVersion {
		// Not "retired": the load fails, the boot retry keeps trying, and the
		// mismatch stays in the log until the custodian is upgraded.
		return DelegateSeed{}, fmt.Errorf("delegate-seed apiVersion %d for epoch %d, need %d (custodian predates plan-2609-12 slice 07)",
			out.APIVersion, epoch, delegateSeedAPIVersion)
	}
	seed := DelegateSeed{Seed: out.Seed}
	if len(out.Voucher) > 0 {
		v, err := decodeDelegateKeyVoucher(out.Voucher)
		if err != nil {
			return DelegateSeed{}, fmt.Errorf("delegate-seed epoch %d: %w", epoch, err)
		}
		if v.SealerID != p.sealerID || v.Epoch != epoch {
			return DelegateSeed{}, fmt.Errorf("delegate-seed epoch %d: voucher is for sealer %q epoch %d; refusing the response",
				epoch, v.SealerID, v.Epoch)
		}
		if out.VoucherNotAfter != 0 && int64(out.VoucherNotAfter) != v.NotAfter.Unix() {
			return DelegateSeed{}, fmt.Errorf("delegate-seed epoch %d: voucherNotAfter %d differs from voucher claim 4 %d; refusing the response",
				epoch, out.VoucherNotAfter, v.NotAfter.Unix())
		}
		seed.Voucher = v
	}
	if p.logger != nil {
		// Warn, like the other boot-time delegation lines: lanes run the
		// sealer above info, and ops-0016 verifies a rotation from this line
		// (epoch N under version N, epoch N-1 under version N-1).
		attrs := []any{"epoch", epoch, "kmsKeyVersion", out.KMSKeyVersion}
		if seed.Voucher != nil {
			attrs = append(attrs, "voucherNotAfter", seed.Voucher.NotAfter.UTC().Format(time.RFC3339))
		} else {
			attrs = append(attrs, "voucher", "absent (custodian could not sign one; will ask again)")
		}
		p.logger.Warn("delegate seed derived", attrs...)
	}
	return seed, nil
}

// NewSeedProvider selects the seed source: the custodian KMS-MAC endpoint
// when a base URL is configured, else the test-only local seed. Only the
// custodian returns vouchers, so only a custodian provider asserts
// registration (devdocs plan-2609-12 slice 05 change 9).
func NewSeedProvider(cfg Config, httpClient *HTTPClient) (SeedProvider, error) {
	return newSeedProvider(cfg, httpClient, nil)
}

func newSeedProvider(cfg Config, httpClient *HTTPClient, logger *slog.Logger) (SeedProvider, error) {
	if cfg.DelegateSeedCustodianURL != "" {
		return custodianSeedProvider{
			baseURL:    cfg.DelegateSeedCustodianURL,
			token:      cfg.DelegateSeedCustodianToken,
			sealerID:   cfg.SealerID,
			httpClient: httpClient,
			logger:     logger,
		}, nil
	}
	if len(cfg.DelegateSeedLocal) > 0 {
		return localSeedProvider{secret: cfg.DelegateSeedLocal}, nil
	}
	return nil, fmt.Errorf("no delegate seed source: set DELEGATE_SEED_CUSTODIAN_URL or DELEGATE_SEED")
}
