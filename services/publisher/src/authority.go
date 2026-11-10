package publisher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/fxamacker/cbor/v2"

	"github.com/forestrie/arbor/services/pkgs/logid"
)

// LogAuthority reports whether univocity has found a log's first on-chain
// registration in conflict with the log's claim (devdocs ADR-0075 decision
// 8). A conflicted log is final: nothing more is published for it.
//
// This is the only question the publisher asks univocity. The forest's
// chain binding still comes from public R2 genesis (ADR-0047), and a log
// in any other state is published as usual: the contract checks every
// publish against the owner's on-chain accumulator, so submitting one
// early is harmless, and a log's own first checkpoint is what lets
// univocity compare its registration with its claim.
type LogAuthority interface {
	Conflicted(ctx context.Context, logID logid.UUID) (bool, error)
}

// authorityConflicted is univocity's state for a conflicted log.
const authorityConflicted = "conflicted"

// UnivocityAuthority asks univocity's GET /api/logs/{logId}/authority (the
// wire shape is services/univocity authorityResponse). A conflicted answer
// is remembered for the life of the process. So is a final one, up to
// verdictCap logs; past that, and for any answer not final, univocity is
// asked again on the next call.
type UnivocityAuthority struct {
	baseURL string
	client  *http.Client

	mu         sync.Mutex
	conflicted map[logid.UUID]struct{}
	settled    map[logid.UUID]struct{} // final and not conflicted
}

// NewUnivocityAuthority returns a LogAuthority for the univocity service at
// baseURL. The authority read is unauthenticated.
func NewUnivocityAuthority(baseURL string, client *http.Client) *UnivocityAuthority {
	return &UnivocityAuthority{
		baseURL:    strings.TrimRight(baseURL, "/"),
		client:     client,
		conflicted: make(map[logid.UUID]struct{}),
		settled:    make(map[logid.UUID]struct{}),
	}
}

// authorityAnswer is the part of univocity's authority record the publisher
// reads.
type authorityAnswer struct {
	State string `cbor:"state"`
	Final bool   `cbor:"final"`
}

// Conflicted reports whether univocity reports logID conflicted. Any failure
// to get an answer is an error, which callers treat as transient.
func (a *UnivocityAuthority) Conflicted(ctx context.Context, logID logid.UUID) (bool, error) {
	a.mu.Lock()
	_, conflicted := a.conflicted[logID]
	_, settled := a.settled[logID]
	a.mu.Unlock()
	if conflicted || settled {
		return conflicted, nil
	}

	url := a.baseURL + "/api/logs/" + logID.String() + "/authority"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/cbor")
	resp, err := a.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("univocity authority %s: %w", logID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false, fmt.Errorf("univocity authority %s: read body: %w", logID, err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("univocity authority %s: status %d", logID, resp.StatusCode)
	}
	var answer authorityAnswer
	if err := cbor.Unmarshal(body, &answer); err != nil {
		return false, fmt.Errorf("univocity authority %s: decode: %w", logID, err)
	}
	conflicted = answer.State == authorityConflicted
	a.mu.Lock()
	switch {
	case conflicted:
		a.conflicted[logID] = struct{}{}
	case answer.Final && len(a.settled) < verdictCap:
		a.settled[logID] = struct{}{}
	}
	a.mu.Unlock()
	return conflicted, nil
}
