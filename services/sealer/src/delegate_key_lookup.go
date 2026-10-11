package sealer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// delegateKeyLookupTimeout bounds one lookup request so a hung coordinator
// cannot stall the readiness poll.
const delegateKeyLookupTimeout = 15 * time.Second

// coordinatorDelegateKeyLookup asks the delegation coordinator whether a
// standing delegate key is registered: GET /api/sealer/delegate-keys/{pubkeyHash}
// (canopy delegation-coordinator, handlers/get-delegate-key.ts; devdocs
// plan-2609-12 slice 04). The coordinator answers 200 only when the key is on
// EVERY shard, because a log's coverage retrieval reads only that log's
// shard; a partial registration is a 404 the custodian's registration outbox
// completes. The sealer never registers (the custodian does, with a voucher);
// it only observes.
type coordinatorDelegateKeyLookup struct {
	baseURL    string
	token      string
	httpClient *HTTPClient
}

// Registered reports whether pubkeyHash is registered on every shard. A 404 is
// (false, detail, nil), detail carrying the coordinator's reason (missing, or
// registered on k of n shards). Any other answer or a transport failure is an
// error: registration is then unknown, not absent.
func (l coordinatorDelegateKeyLookup) Registered(ctx context.Context, pubkeyHash string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, delegateKeyLookupTimeout)
	defer cancel()
	endpoint := strings.TrimRight(strings.TrimSpace(l.baseURL), "/") + "/api/sealer/delegate-keys/" + pubkeyHash
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return false, "", fmt.Errorf("build delegate key lookup: %w", err)
	}
	if l.token != "" {
		req.Header.Set("Authorization", "Bearer "+l.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := l.httpClient.Do(ctx, req)
	if err != nil {
		return false, "", fmt.Errorf("delegate key lookup: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusOK:
		return true, "", nil
	case http.StatusNotFound:
		return false, truncateForLog(body, 300), nil
	default:
		return false, "", fmt.Errorf("delegate key lookup status=%d body=%s", resp.StatusCode, truncateForLog(body, 300))
	}
}
