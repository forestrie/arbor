package sealer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/fxamacker/cbor/v2"
)

// AuthorityBinding is the authority univocity resolves for a log: the
// authoritative root key plus the chain binding. The sealer verifies the
// (untrusted) delegation certificate locally against SigningKey; the actual
// authorization decision is that local verification, not this lookup.
type AuthorityBinding struct {
	SigningKey LogSigningKey
	// Final is univocity's word that the answer cannot change.
	Final           bool
	RootLogIDHex    string
	ChainID         string
	ContractAddress string
	Source          string
}

// AuthorityResolver asks univocity, the only source of root keys (devdocs
// ADR-0075 decision 5), for the root key and chain binding of a log. It is a
// non-mutating lookup keyed by logId; the delegation certificate is never
// sent. It returns a key only for a log univocity reports anchored with no
// ancestor blocking it. Otherwise it fails with ErrAuthorityPending, which is
// transient, or ErrLogConflicted, which is final.
type AuthorityResolver interface {
	ResolveAuthority(ctx context.Context, logIdHex string) (AuthorityBinding, error)
}

// Univocity's authority states that the sealer acts on; every other state
// (reserved, committed, sequenced) is pending.
const (
	authorityAnchored   = "anchored"
	authorityConflicted = "conflicted"
)

// authorityResponse mirrors univocity's GET /api/logs/{logId}/authority
// output (arbor services/univocity handlers.go).
type authorityResponse struct {
	LogID      []byte `cbor:"logId,omitempty"`
	RootLogID  []byte `cbor:"rootLogId,omitempty"`
	OwnerLogID []byte `cbor:"ownerLogId,omitempty"`
	State      string `cbor:"state"`
	Alg        int64  `cbor:"alg,omitempty"`
	Key        []byte `cbor:"key,omitempty"`
	ChainID    string `cbor:"chainId,omitempty"`
	Contract   string `cbor:"contract,omitempty"`
	Source     string `cbor:"source,omitempty"`
	BlockedBy  []byte `cbor:"blockedBy,omitempty"`
	Final      bool   `cbor:"final"`
}

// AuthorityStatusError reports a non-200 authority response with its HTTP
// status so callers can classify a 404 — the univocity instance has no
// locator for the log, permanent until repaired — apart from transient 5xx
// (plan-2607-10 slice 04).
type AuthorityStatusError struct {
	StatusCode int
	LogIdHex   string
}

func (e *AuthorityStatusError) Error() string {
	return fmt.Sprintf("authority returned status=%d for log %s", e.StatusCode, e.LogIdHex)
}

// IsAuthorityNotFound reports whether err is an authority 404: retrying
// without repair (idempotent grant re-post, or a rootLogId hint) cannot
// succeed.
func IsAuthorityNotFound(err error) bool {
	var se *AuthorityStatusError
	return errors.As(err, &se) && se.StatusCode == http.StatusNotFound
}

// HTTPAuthorityResolver calls univocity GET {BaseURL}/api/logs/{logId}/authority.
type HTTPAuthorityResolver struct {
	BaseURL    string
	Token      string
	HTTPClient *HTTPClient
}

// ResolveAuthority fetches the root key and chain binding for an anchored
// log; see AuthorityResolver.
func (c *HTTPAuthorityResolver) ResolveAuthority(
	ctx context.Context,
	logIdHex string,
) (AuthorityBinding, error) {
	if c == nil || c.HTTPClient == nil {
		return AuthorityBinding{}, fmt.Errorf("authority resolver not configured")
	}
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		return AuthorityBinding{}, fmt.Errorf("authority base URL is empty")
	}
	logIdHex = strings.TrimSpace(logIdHex)
	if logIdHex == "" {
		return AuthorityBinding{}, fmt.Errorf("log ID is empty")
	}

	apiLogID, err := logIDAPISegment(logIdHex)
	if err != nil {
		return AuthorityBinding{}, err
	}
	endpoint := base + "/api/logs/" + apiLogID + "/authority"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return AuthorityBinding{}, fmt.Errorf("build authority request: %w", err)
	}
	req.Header.Set("Accept", "application/cbor")
	if token := strings.TrimSpace(c.Token); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.HTTPClient.Do(ctx, req)
	if err != nil {
		return AuthorityBinding{}, fmt.Errorf("authority request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return AuthorityBinding{}, fmt.Errorf("read authority response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return AuthorityBinding{}, &AuthorityStatusError{
			StatusCode: resp.StatusCode,
			LogIdHex:   logIdHex,
		}
	}

	var record authorityResponse
	if err := cbor.Unmarshal(body, &record); err != nil {
		return AuthorityBinding{}, fmt.Errorf("decode authority response: %w", err)
	}
	switch {
	case record.State == authorityConflicted:
		return AuthorityBinding{}, fmt.Errorf("%w: log %s", ErrLogConflicted, logIdHex)
	case record.State != authorityAnchored:
		return AuthorityBinding{}, fmt.Errorf("%w: log %s is %q", ErrAuthorityPending, logIdHex, record.State)
	case len(record.BlockedBy) > 0:
		return AuthorityBinding{}, fmt.Errorf("%w: log %s is blocked by ancestor %s",
			ErrAuthorityPending, logIdHex, logid.FromPaddedWire32(record.BlockedBy))
	}

	signingKey, err := logSigningKeyFromAlgKey(record.Alg, record.Key)
	if err != nil {
		return AuthorityBinding{}, fmt.Errorf("authority key: %w", err)
	}
	rootUUID := logid.FromPaddedWire32(record.RootLogID)
	return AuthorityBinding{
		SigningKey:      signingKey,
		Final:           record.Final,
		RootLogIDHex:    hex.EncodeToString(rootUUID[:]),
		ChainID:         strings.TrimSpace(record.ChainID),
		ContractAddress: strings.TrimSpace(record.Contract),
		Source:          strings.TrimSpace(record.Source),
	}, nil
}
