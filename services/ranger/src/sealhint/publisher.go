// Package sealhint publishes seal hints to the sealer's Cloudflare Queue
// (ADR-0007 phase 1, FOR-380).
//
// A seal hint is the trigger message that wakes the sealer to run
// CheckpointLog for a massif. Hints are at-least-once and carry no authority:
// the sealer re-derives all work from R2 state, so lost, duplicate, or
// spurious hints are harmless. Publishing is fire-and-forget — a failure is
// logged and counted, never surfaced to the commit path; the R2 event
// notification remains the lagging backstop.
package sealhint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/logredact"
	"github.com/forestrie/arbor/services/ranger"
	"github.com/forestrie/arbor/services/ranger/metrics"
)

// Source identifies ranger-originated hints so the sealer's
// sealer_seal_trigger_total{source} metric can attribute the wake path. The
// field is unknown to (and ignored by) sealers that predate it.
const Source = "ranger_hint"

const (
	// publishAttempts bounds the fire-and-forget retry (ADR-0007: "bounded
	// retry (e.g. 2 attempts, short timeout)").
	publishAttempts = 2
	// attemptTimeout bounds each publish attempt so a slow queue API cannot
	// stall the poll loop.
	attemptTimeout = 2 * time.Second
	// retryDelay separates the two attempts.
	retryDelay = 200 * time.Millisecond
)

// hint is the seal hint payload. It reproduces the R2 PutObject event
// notification shape the sealer's consumer already parses — including the
// Action gate (consumer.go rejects non-PutObject notifications) — plus the
// hintSource marker, which older sealers ignore (unknown JSON field).
type hint struct {
	Action     string     `json:"action"`
	Object     hintObject `json:"object"`
	EventTime  string     `json:"eventTime"`
	HintSource string     `json:"hintSource"`
}

type hintObject struct {
	Key string `json:"key"`
}

// pushRequest is the Cloudflare Queues HTTP publish body. content_type "text"
// makes the pull deliver the body as a JSON string token — the exact encoding
// the sealer's consumer double-decodes for R2 event notifications.
type pushRequest struct {
	Body        string `json:"body"`
	ContentType string `json:"content_type"`
}

// Publisher publishes seal hints to the sealer's Cloudflare Queue.
type Publisher struct {
	pushURL    string
	token      string
	httpClient *ranger.HTTPClient
	logger     *slog.Logger
	metrics    *metrics.Metrics
	now        func() time.Time // injectable for tests
}

// New builds a Publisher from config. Returns nil when SealHintQueueURL is
// empty (feature off) — a nil Publisher is safe to call.
func New(cfg ranger.Config, httpClient *ranger.HTTPClient, logger *slog.Logger, m *metrics.Metrics) *Publisher {
	if strings.TrimSpace(cfg.SealHintQueueURL) == "" {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	base := strings.TrimSpace(cfg.SealHintQueueURL)
	base = strings.TrimSuffix(base, "/")
	base = strings.TrimSuffix(base, "/messages")
	return &Publisher{
		pushURL:    base + "/messages",
		token:      cfg.SealHintQueueToken,
		httpClient: httpClient,
		logger:     logger,
		metrics:    m,
		now:        time.Now,
	}
}

// PublishSealHints publishes one seal hint per massif object key.
// Fire-and-forget: failures are logged and counted, never returned — the
// commit path has already succeeded and must not be affected.
func (p *Publisher) PublishSealHints(ctx context.Context, objectKeys []string) {
	if p == nil {
		return
	}
	for _, key := range objectKeys {
		p.publish(ctx, key)
	}
}

func (p *Publisher) publish(ctx context.Context, objectKey string) {
	body, err := p.encodeHint(objectKey)
	if err != nil {
		// Unreachable in practice (static shape), but keep the accounting honest.
		p.recordFailure(objectKey, fmt.Errorf("encode hint: %w", err))
		return
	}

	var lastErr error
	for attempt := 1; attempt <= publishAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				p.recordFailure(objectKey, ctx.Err())
				return
			case <-time.After(retryDelay):
			}
		}
		if lastErr = p.attempt(ctx, body); lastErr == nil {
			if p.metrics != nil {
				p.metrics.RecordSealHintPublish(true)
			}
			p.logger.Debug("seal hint published",
				"objectKey", objectKey,
				"attempt", attempt,
			)
			return
		}
	}
	p.recordFailure(objectKey, lastErr)
}

func (p *Publisher) encodeHint(objectKey string) ([]byte, error) {
	note, err := json.Marshal(hint{
		Action:     "PutObject",
		Object:     hintObject{Key: objectKey},
		EventTime:  p.now().UTC().Format(time.RFC3339),
		HintSource: Source,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(pushRequest{
		Body:        string(note),
		ContentType: "text",
	})
}

func (p *Publisher) attempt(ctx context.Context, body []byte) error {
	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()

	req, err := http.NewRequest(http.MethodPost, p.pushURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(attemptCtx, req)
	if err != nil {
		return fmt.Errorf("push: %w", err)
	}
	defer resp.Body.Close()
	// Drain so the connection is reusable.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("push failed: status=%d", resp.StatusCode)
	}
	return nil
}

func (p *Publisher) recordFailure(objectKey string, err error) {
	if p.metrics != nil {
		p.metrics.RecordSealHintPublish(false)
	}
	p.logger.Warn("seal hint publish failed; R2 event backstop will trigger the seal",
		"objectKey", objectKey,
		"pushURL_sha256", logredact.StringSHA256Hex(p.pushURL),
		"error", err,
	)
}
