package sealer

import (
	"context"
	"encoding/hex"
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
	SigningKey      LogSigningKey
	RootLogIDHex    string
	ChainID         string
	ContractAddress string
	Source          string
}

// AuthorityResolver asks the trusted univocity service for the authoritative
// root key (and chain binding) of a log, resolving cold logs from the
// chain-valid grant chain. It is a non-mutating lookup keyed by logId; the
// delegation certificate is never sent.
type AuthorityResolver interface {
	ResolveAuthority(ctx context.Context, logIdHex string) (AuthorityBinding, error)
}

// authorityResponse mirrors univocity's GET /api/logs/{logId}/authority output.
type authorityResponse struct {
	LogID     []byte `cbor:"logId,omitempty"`
	RootLogID []byte `cbor:"rootLogId,omitempty"`
	Alg       string `cbor:"alg,omitempty"`
	X         []byte `cbor:"x,omitempty"`
	Y         []byte `cbor:"y,omitempty"`
	ChainID   string `cbor:"chainId,omitempty"`
	Contract  string `cbor:"contract,omitempty"`
	Source    string `cbor:"source,omitempty"`
}

// HTTPAuthorityResolver calls univocity GET {BaseURL}/api/logs/{logId}/authority.
type HTTPAuthorityResolver struct {
	BaseURL    string
	Token      string
	HTTPClient *HTTPClient
}

// ResolveAuthority fetches the authoritative root key + chain binding for a log.
// A non-200 response is an error so the caller fails closed; the sealer then
// verifies the delegation certificate locally against the returned key.
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
		return AuthorityBinding{}, fmt.Errorf(
			"authority returned status=%d for log %s", resp.StatusCode, logIdHex,
		)
	}

	var record authorityResponse
	if err := cbor.Unmarshal(body, &record); err != nil {
		return AuthorityBinding{}, fmt.Errorf("decode authority response: %w", err)
	}
	pemStr, err := EncodeECDSAPublicKeyPEMFromXY(record.Alg, record.X, record.Y)
	if err != nil {
		return AuthorityBinding{}, fmt.Errorf("authority key: %w", err)
	}
	rootUUID := logid.FromPaddedWire32(record.RootLogID)
	return AuthorityBinding{
		SigningKey:      LogSigningKey{PublicKeyPEM: pemStr, Alg: strings.TrimSpace(record.Alg)},
		RootLogIDHex:    hex.EncodeToString(rootUUID[:]),
		ChainID:         strings.TrimSpace(record.ChainID),
		ContractAddress: strings.TrimSpace(record.Contract),
		Source:          strings.TrimSpace(record.Source),
	}, nil
}
