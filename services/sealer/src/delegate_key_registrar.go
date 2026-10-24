package sealer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// delegateKeyAssertTimeout bounds one assertion so a hung coordinator cannot
// stall a key's assertion loop.
const delegateKeyAssertTimeout = 15 * time.Second

// registerDelegateKeyEntry and registerDelegateKeysBody are the JSON body of
// POST /api/sealer/delegate-keys. Wire owner: canopy delegation-coordinator
// types/register-delegate-keys-request.ts (handlers/post-delegate-keys.ts).
type registerDelegateKeyEntry struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"publicKey"` // base64 canonical COSE_Key CBOR
	Epoch     uint32 `json:"epoch"`
	NotAfter  int64  `json:"notAfter"` // Unix seconds: the voucher's claim 4
	Voucher   string `json:"voucher"`  // base64 untagged COSE_Sign1
}

type registerDelegateKeysBody struct {
	SealerID string                     `json:"sealerId"`
	Keys     []registerDelegateKeyEntry `json:"keys"`
}

// assertKind classifies one assertion answer (devdocs plan-2609-12 slice 05
// change 3).
type assertKind int

const (
	// assertOK is any 2xx: the coordinator holds the row.
	assertOK assertKind = iota
	// assertConflict is the 409 for another key holding this sealer and
	// epoch (ruling 4′). The sealer keeps asserting, so an operator's delete
	// heals it without a restart.
	assertConflict
	// assertTombstoned is the 410 for a retired key (ruling 8). Final.
	assertTombstoned
	// assertVoucherRefused is a 400 that a fresh voucher fixes (refused or
	// expired; see voucherFixes): refresh vouchers now, then retry.
	assertVoucherRefused
	// assertRetry is any other status or a transport error.
	assertRetry
)

func (k assertKind) String() string {
	return [...]string{"ok", "conflict", "tombstoned", "voucher-refused", "retry"}[k]
}

// assertResult is one assertion's outcome; detail carries the coordinator's
// problem title and detail for the log.
type assertResult struct {
	kind   assertKind
	status int
	detail string
	err    error
}

// coordinatorDelegateKeyRegistrar asserts the sealer's standing delegate keys
// with the delegation coordinator: POST /api/sealer/delegate-keys with the
// coordinator bearer (COORDINATOR_REGISTER_URL/_TOKEN). The coordinator
// verifies the custodian's voucher, fans the row out to every shard, and
// treats a registration identical to the stored row as a no-op.
type coordinatorDelegateKeyRegistrar struct {
	baseURL    string
	token      string
	httpClient *HTTPClient
}

// assert registers one key. One key per request, so a refusal for N-1
// never blocks N.
func (c coordinatorDelegateKeyRegistrar) assert(ctx context.Context, sealerID string, key registerDelegateKeyEntry) assertResult {
	payload, err := json.Marshal(registerDelegateKeysBody{SealerID: sealerID, Keys: []registerDelegateKeyEntry{key}})
	if err != nil {
		return assertResult{kind: assertRetry, err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, delegateKeyAssertTimeout)
	defer cancel()
	endpoint := strings.TrimRight(strings.TrimSpace(c.baseURL), "/") + "/api/sealer/delegate-keys"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return assertResult{kind: assertRetry, err: fmt.Errorf("build delegate key assertion: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(ctx, req)
	if err != nil {
		return assertResult{kind: assertRetry, err: fmt.Errorf("delegate key assertion: %w", err)}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	res := assertResult{status: resp.StatusCode, kind: assertRetry}
	var problem struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &problem) == nil && (problem.Title != "" || problem.Detail != "") {
		res.detail = strings.TrimSpace(problem.Title + ": " + problem.Detail)
	} else {
		res.detail = truncateForLog(body, 300)
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		res.kind = assertOK
	case resp.StatusCode == http.StatusConflict:
		res.kind = assertConflict
	case resp.StatusCode == http.StatusGone:
		res.kind = assertTombstoned
	case resp.StatusCode == http.StatusBadRequest && voucherFixes(problem.Title, problem.Detail):
		res.kind = assertVoucherRefused
	}
	return res
}

// Coordinator 400s that a fresh voucher fixes. Every problem there has type
// "about:blank", so the title and detail are what is stable. Wire owner:
// canopy packages/apps/delegation-coordinator src/handlers/post-delegate-keys.ts
// ("Invalid voucher": the voucher failed verification, whatever the reason)
// and src/durableobjects/delegation-store.ts parseDelegateKeyBatch ("Invalid
// request" with notAfter in the past, which the sealer sends as the voucher's
// claim 4). Other "Invalid request" details are malformed bodies (base64,
// required fields) that a new voucher would not change.
const (
	coordinatorProblemInvalidVoucher  = "Invalid voucher"
	coordinatorProblemInvalidRequest  = "Invalid request"
	coordinatorDetailNotAfterInFuture = "notAfter must be in the future"
)

func voucherFixes(title, detail string) bool {
	return title == coordinatorProblemInvalidVoucher ||
		(title == coordinatorProblemInvalidRequest && detail == coordinatorDetailNotAfterInFuture)
}
