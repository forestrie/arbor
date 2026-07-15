package sealer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	"github.com/forestrie/arbor/services/sealer/metrics"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// ResyncManager runs the level-triggered resync loop (ADR-0007 phase-3 sweep /
// plan-2607-04): the correctness backstop to the edge-triggered queue path. It
// pages the coordinator active-delegation set and, for each log whose massif
// head has advanced past its latest checkpoint, re-drives a seal IN-PROCESS via
// CheckpointLog. The sealer stays strictly pull-only — it never publishes to
// its own seal queue (that would be a self-amplification loop).
//
// Freshness is by MMR size, not massif index: a log can advance within the same
// massif (more leaves, no new massif object), which REPLACES that massif's
// checkpoint. So the decision is headMMRSize > lastCheckpointTreeSize2.
//
// RAM state (cursor, per-log height and last-sealed size) is lost on restart
// and self-heals: the next full cycle re-discovers heights and re-reads
// checkpoints. One page is processed per tick, spreading a large active set
// over many ticks.
type ResyncManager struct {
	cfg        Config
	httpClient *HTTPClient
	logger     *slog.Logger
	leaseMgr   *DelegationLeaseManager
	metrics    *metrics.Metrics

	s3Client *s3.Client

	mu          sync.Mutex
	cursor      string
	factories   map[uint8]*merklelog.Factory
	heightByLog map[string]uint8
	heightMiss  map[string]time.Time // logID -> earliest re-probe time (negative cache)
	sealedByLog map[string]uint64
}

// activeLog mirrors one row of the coordinator GET /api/delegations/active
// response. mmrEnd is the furthest authorized index (a hint), not necessarily
// the head — with DELEGATION_RANGE_PAD it can sit ahead of the true head.
type activeLog struct {
	LogIDHex32 string `json:"logIdHex32"`
	ExpiresAt  int64  `json:"expiresAt"`
	MmrStart   *int64 `json:"mmrStart"`
	MmrEnd     *int64 `json:"mmrEnd"`
}

type activePage struct {
	Logs   []activeLog `json:"logs"`
	Cursor *string     `json:"cursor"`
}

// NewResyncManager builds a resync manager sharing the sealer's HTTP client and
// a single S3 object client (reused across all logs and heights).
func NewResyncManager(cfg Config, httpClient *HTTPClient, logger *slog.Logger, leaseMgr *DelegationLeaseManager, m *metrics.Metrics) (*ResyncManager, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s3Client, err := s3.NewClientWithCredentials(
		cfg.R2URL, "", cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, cfg.AWSRegion, httpClient, logger,
	)
	if err != nil {
		return nil, fmt.Errorf("resync: build s3 client: %w", err)
	}
	return &ResyncManager{
		cfg:         cfg,
		httpClient:  httpClient,
		logger:      logger,
		leaseMgr:    leaseMgr,
		metrics:     m,
		s3Client:    s3Client,
		factories:   map[uint8]*merklelog.Factory{},
		heightByLog: map[string]uint8{},
		heightMiss:  map[string]time.Time{},
		sealedByLog: map[string]uint64{},
	}, nil
}

// Run drives the resync loop until ctx is cancelled. It is a no-op (with a
// clear log) when resync is not enabled.
func (r *ResyncManager) Run(ctx context.Context) {
	if !r.cfg.ResyncEnabled() {
		r.logger.Info("resync loop disabled (set RESYNC_MASSIF_HEIGHTS to enable)")
		return
	}
	r.logger.Info("starting resync loop",
		"interval", r.cfg.ResyncInterval,
		"pageSize", r.cfg.ResyncPageSize,
		"graceSeconds", r.cfg.ResyncGraceSeconds,
		"concurrency", r.cfg.ResyncConcurrency,
		"candidateHeights", r.cfg.ResyncMassifHeights,
	)
	ticker := time.NewTicker(r.cfg.ResyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.logger.Debug("resync loop stopping")
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

// tick fetches one active-set page and checks/re-drives each log in it.
func (r *ResyncManager) tick(ctx context.Context) {
	page, err := r.fetchActivePage(ctx, r.cursor)
	if err != nil {
		// Reset the cursor so a persistent 4xx (e.g. a reshard that invalidates
		// the held opaque cursor) cannot wedge the backstop: the next tick
		// restarts the walk from the first shard rather than re-sending a dead
		// cursor forever.
		r.logger.Warn("resync: active-set page fetch failed; restarting walk next tick", "error", err)
		r.mu.Lock()
		r.cursor = ""
		r.mu.Unlock()
		return
	}
	if r.metrics != nil {
		r.metrics.RecordResyncPage(len(page.Logs))
	}

	// Advance the cursor: nil means the full set was walked, restart from the
	// beginning next tick.
	r.mu.Lock()
	if page.Cursor != nil {
		r.cursor = *page.Cursor
	} else {
		r.cursor = ""
	}
	r.mu.Unlock()

	conc := r.cfg.ResyncConcurrency
	if conc < 1 {
		conc = 1
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for _, lg := range page.Logs {
		lg := lg
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r.checkAndReseal(ctx, lg)
		}()
	}
	wg.Wait()
}

// checkAndReseal runs the freshness check for one log and, if its head has
// advanced past the latest checkpoint, re-drives a seal via CheckpointLog.
func (r *ResyncManager) checkAndReseal(ctx context.Context, lg activeLog) {
	if r.metrics != nil {
		r.metrics.IncResyncChecks()
	}
	logIDBytes, err := hex.DecodeString(lg.LogIDHex32)
	if err != nil || len(logIDBytes) != 16 {
		r.logger.Warn("resync: invalid logId", "logId", lg.LogIDHex32)
		return
	}

	// Range-hint fast path: mmrEnd is the furthest authorized index. If a prior
	// checkpoint read already covers it, nothing more can be sealed under the
	// current delegation — skip the R2 head read entirely. Pure fast-path: a log
	// with no cached sealed size falls through to the authoritative check.
	if lg.MmrEnd != nil && *lg.MmrEnd >= 0 {
		r.mu.Lock()
		cached, ok := r.sealedByLog[lg.LogIDHex32]
		r.mu.Unlock()
		if ok && cached >= uint64(*lg.MmrEnd) {
			return
		}
	}

	// resolveHeight owns miss logging (rate-limited, below WARN after the first
	// miss) so a delegation-in-advance log with no massifs yet does not spam.
	height, ok := r.resolveHeight(ctx, lg.LogIDHex32, logIDBytes)
	if !ok {
		return
	}

	headMMRSize, empty, err := r.headSize(ctx, height, logIDBytes)
	if err != nil {
		r.logger.Warn("resync: head massif read failed", "logId", lg.LogIDHex32, "height", height, "error", err)
		return
	}
	if empty {
		return // no massif data yet; nothing to seal
	}

	sealedSize, err := r.sealedSize(ctx, height, logIDBytes, lg.LogIDHex32)
	if err != nil {
		r.logger.Warn("resync: checkpoint read failed", "logId", lg.LogIDHex32, "height", height, "error", err)
		return
	}

	if headMMRSize <= sealedSize {
		return // fresh: latest checkpoint already covers the head
	}

	// The head advanced past the sealed size (possibly within the same massif,
	// replacing its checkpoint). Re-drive the same seal path the queue uses.
	if r.metrics != nil {
		r.metrics.IncResyncReseals()
		r.metrics.RecordSealTrigger(metrics.SealTriggerSourceSweep)
	}
	svc := SealerService{
		Cfg:          r.cfg,
		HTTPClient:   r.httpClient,
		Logger:       r.logger,
		LeaseManager: r.leaseMgr,
		Metrics:      r.metrics,
	}
	if err := CheckpointLog(ctx, svc, logIDBytes, height); err != nil {
		if errors.Is(err, ErrDelegationPending) || errors.Is(err, ErrDelegationExpired) {
			r.logger.Info("resync: reseal deferred on delegation; will retry next cycle",
				"logId", lg.LogIDHex32, "height", height, "headMMRSize", headMMRSize, "sealedSize", sealedSize, "error", err)
			return
		}
		r.logger.Warn("resync: reseal failed", "logId", lg.LogIDHex32, "height", height, "error", err)
		return
	}
	r.logger.Info("resync: re-drove seal for lagging log",
		"logId", lg.LogIDHex32, "height", height, "headMMRSize", headMMRSize, "prevSealedSize", sealedSize)
	// The head is now sealed; update the cache so subsequent cycles skip it
	// until it advances again.
	r.mu.Lock()
	r.sealedByLog[lg.LogIDHex32] = headMMRSize
	r.mu.Unlock()
}

// resolveHeight returns the massif height for a log, discovering it from R2 by
// probing the configured candidate heights and caching the hit. Misses are
// negative-cached with a backoff so a delegation-in-advance log (active cert,
// no massifs yet — normal) is not re-probed (len(heights) LISTs) every tick,
// and the miss is logged at WARN only on the first occurrence per log; a
// persistent miss across all logs still surfaces (bad RESYNC_MASSIF_HEIGHTS).
func (r *ResyncManager) resolveHeight(ctx context.Context, logIDHex string, logIDBytes []byte) (uint8, bool) {
	now := time.Now()

	r.mu.Lock()
	if h, ok := r.heightByLog[logIDHex]; ok {
		r.mu.Unlock()
		return h, true
	}
	retryAt, missedBefore := r.heightMiss[logIDHex]
	if missedBefore && now.Before(retryAt) {
		r.mu.Unlock()
		return 0, false // within negative-cache backoff; skip the re-probe
	}
	r.mu.Unlock()

	for _, cand := range r.cfg.ResyncMassifHeights {
		prefix, err := r.massifPrefix(cand, logIDBytes)
		if err != nil {
			continue
		}
		page, err := r.s3Client.ListObjects(ctx, prefix, "", 1)
		if err != nil {
			r.logger.Debug("resync: height probe list failed", "logId", logIDHex, "height", cand, "error", err)
			continue
		}
		if len(page.Objects) > 0 {
			r.mu.Lock()
			r.heightByLog[logIDHex] = cand
			delete(r.heightMiss, logIDHex)
			r.mu.Unlock()
			return cand, true
		}
	}

	backoff := 10 * r.cfg.ResyncInterval
	if backoff < time.Minute {
		backoff = time.Minute
	}
	r.mu.Lock()
	r.heightMiss[logIDHex] = now.Add(backoff)
	r.mu.Unlock()
	if !missedBefore {
		r.logger.Warn("resync: no massifs found for log at any candidate height "+
			"(normal for a not-yet-written log; check RESYNC_MASSIF_HEIGHTS if this persists for all logs)",
			"logId", logIDHex, "candidateHeights", r.cfg.ResyncMassifHeights)
	} else {
		r.logger.Debug("resync: still no massifs for log", "logId", logIDHex)
	}
	return 0, false
}

// headSize returns the current head MMR size for a log, computed from the head
// massif object's size (from a LIST — no massif download). empty is true when
// the log has no massif objects yet.
func (r *ResyncManager) headSize(ctx context.Context, height uint8, logIDBytes []byte) (size uint64, empty bool, err error) {
	prefix, err := r.massifPrefix(height, logIDBytes)
	if err != nil {
		return 0, false, err
	}
	var (
		haveHead  bool
		headIndex uint32
		headBytes int64
		cont      string
	)
	for {
		page, err := r.s3Client.ListObjects(ctx, prefix, cont, 1000)
		if err != nil {
			return 0, false, fmt.Errorf("list massifs: %w", err)
		}
		for _, obj := range page.Objects {
			idx, err := massifstorage.GetObjectIndex(obj.Key, massifstorage.ObjectMassifData)
			if err != nil {
				continue // not a massif-data object
			}
			if !haveHead || idx >= headIndex {
				haveHead = true
				headIndex = idx
				headBytes = obj.Size
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		cont = page.NextContinuationToken
	}
	if !haveHead {
		return 0, true, nil
	}
	return headMMRSizeFromObjectSize(height, headIndex, headBytes), false, nil
}

// sealedSize returns the MMR size covered by the log's latest checkpoint,
// using the per-log cache when present. A log with no checkpoint yet reports 0
// (fully unsealed).
func (r *ResyncManager) sealedSize(ctx context.Context, height uint8, logIDBytes []byte, logIDHex string) (uint64, error) {
	r.mu.Lock()
	cached, ok := r.sealedByLog[logIDHex]
	r.mu.Unlock()
	if ok {
		return cached, nil
	}

	store, err := r.storeForHeight(height, logIDBytes)
	if err != nil {
		return 0, err
	}
	cpIdx, err := store.HeadIndex(ctx, massifstorage.ObjectCheckpoint)
	if errors.Is(err, massifstorage.ErrLogEmpty) {
		r.cacheSealed(logIDHex, 0)
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("head checkpoint index: %w", err)
	}
	data, err := store.CheckpointRead(ctx, cpIdx)
	if err != nil {
		return 0, fmt.Errorf("read checkpoint %d: %w", cpIdx, err)
	}
	receipt, err := massifs.DecodeCheckpointReceipt(data)
	if err != nil {
		return 0, fmt.Errorf("decode checkpoint %d: %w", cpIdx, err)
	}
	sealed := receipt.Proof.TreeSize2
	r.cacheSealed(logIDHex, sealed)
	return sealed, nil
}

func (r *ResyncManager) cacheSealed(logIDHex string, size uint64) {
	r.mu.Lock()
	r.sealedByLog[logIDHex] = size
	r.mu.Unlock()
}

// storeForHeight returns a merklelog store for the log, reusing a per-height
// factory (the object client is height-independent).
func (r *ResyncManager) storeForHeight(height uint8, logIDBytes []byte) (*merklelog.Store, error) {
	r.mu.Lock()
	factory, ok := r.factories[height]
	if !ok {
		f, err := merklelog.NewFactory(r.s3Client, height, r.logger)
		if err != nil {
			r.mu.Unlock()
			return nil, fmt.Errorf("build factory (height=%d): %w", height, err)
		}
		r.factories[height] = f
		factory = f
	}
	r.mu.Unlock()
	return factory.NewStore(massifstorage.LogID(logIDBytes))
}

// massifPrefix builds the full R2 listing prefix for a log's massif objects:
// v2/merklelog/massifs/{height}/{uuid}/.
func (r *ResyncManager) massifPrefix(height uint8, logIDBytes []byte) (string, error) {
	base, err := massifstorage.StorageObjectPrefixWithHeight(
		massifstorage.LogID(logIDBytes), height, massifstorage.ObjectMassifData,
	)
	if err != nil {
		return "", err
	}
	return massifstorage.V2MerklelogMassifsPrefix + "/" + base, nil
}

// fetchActivePage GETs one page of the coordinator active-delegation set.
func (r *ResyncManager) fetchActivePage(ctx context.Context, cursor string) (*activePage, error) {
	base := strings.TrimRight(strings.TrimSpace(r.cfg.CoordinatorRegisterURL), "/")
	endpoint := fmt.Sprintf("%s/api/delegations/active?graceSeconds=%d&limit=%d",
		base, r.cfg.ResyncGraceSeconds, r.cfg.ResyncPageSize)
	if cursor != "" {
		endpoint += "&cursor=" + url.QueryEscape(cursor)
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build active request: %w", err)
	}
	if r.cfg.CoordinatorRegisterToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.CoordinatorRegisterToken)
	}
	resp, err := r.httpClient.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("active request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read active response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("active endpoint status=%d body=%s", resp.StatusCode, truncateForLog(body, 200))
	}
	var page activePage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decode active response: %w", err)
	}
	return &page, nil
}
