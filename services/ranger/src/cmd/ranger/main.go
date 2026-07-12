package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/forestrie/arbor/services/ranger"
	"github.com/forestrie/arbor/services/ranger/committer"
	"github.com/forestrie/arbor/services/ranger/consumer/ingress"
	"github.com/forestrie/arbor/services/ranger/metrics"
	"github.com/forestrie/arbor/services/ranger/sealhint"
	"github.com/prometheus/client_golang/prometheus"
)

// Note: the ci does the right thing with go-releaser automatically, as
// configured in the repo's .goreleaser.yml file.
// Also, task build:fast sets the ldflags correctly for the version, commit, and
// build date so it is clear if a developer build is used.
var (
	version   string
	commit    string
	buildDate string
)

func main() {
	// Load configuration from environment and initialize logger
	cfg := ranger.LoadConfig()
	level, recognized := ranger.ParseLogLevel(cfg.LogLevel)
	logger, _ := ranger.NewLogger(level)

	if !recognized {
		logger.Warn("unrecognized log level value; defaulting to derived level", "input", cfg.LogLevel, "level", level.String())
	}

	// Set the global default logger so packages using slog directly share config
	slog.SetDefault(logger)
	slog.Warn("starting ranger service",
		"version", version,
		"commit", commit,
		"buildDate", buildDate,
	)
	logger.Warn("resolved log level", "input", cfg.LogLevel, "level", level.String())
	cfg.LogConfig(logger)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	// Create context that listens for termination signals
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer stop()

	// Create HTTP client for the committer (separate from consumer clients)
	committerHTTPClient := ranger.NewHTTPClient(logger)

	// Create committer wired to the S3-compatible backend (Cloudflare R2 compatible)
	massifCommitter, err := committer.NewCommitter(cfg, committerHTTPClient, logger)
	if err != nil {
		slog.Error("failed to create committer", "error", err)
		os.Exit(1)
	}
	slog.Info("merklelog committer initialized",
		"massifHeight", cfg.MassifHeight,
		"commitmentEpoch", cfg.CommitmentEpoch,
	)

	// Create metrics registry and metrics
	metricsRegistry := prometheus.NewRegistry()
	metricsHandles := metrics.NewMetrics(metricsRegistry)

	// Start health check server with metrics endpoint
	healthMux := http.NewServeMux()
	setupHealthChecks(healthMux)
	healthMux.Handle("/metrics", metrics.Handler(metricsRegistry))

	healthServer := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: healthMux,
	}

	go func() {
		slog.Warn("starting health check server", "port", cfg.Port)
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("health server failed", "error", err)
		}
	}()

	// Seal hint publisher (ADR-0007 phase 1). Disabled (nil interface) when
	// SEAL_HINT_QUEUE_URL is unset — R2 event notifications alone wake the
	// sealer. Assign through the typed check so a nil *Publisher never becomes
	// a non-nil interface.
	var sealHintPublisher ingress.SealHintPublisher
	if p := sealhint.New(cfg, ranger.NewHTTPClient(logger), logger, metricsHandles); p != nil {
		sealHintPublisher = p
		slog.Info("seal hint publishing enabled")
	} else {
		slog.Info("seal hint publishing disabled (SEAL_HINT_QUEUE_URL unset)")
	}

	// Start ingress consumers (one per shard)
	httpClientFactory := func() *ranger.HTTPClient {
		return ranger.NewHTTPClient(logger)
	}

	consumers, err := ingress.NewShardedConsumers(ctx, cfg, httpClientFactory, logger, massifCommitter, sealHintPublisher, metricsHandles)
	if err != nil {
		slog.Error("failed to discover shards", "error", err)
		os.Exit(1)
	}
	initialShardCount := len(consumers)
	metricsHandles.SetShardCount(initialShardCount)
	slog.Info("starting shard consumers", "shardCount", initialShardCount)

	// Start a consumer goroutine for each shard
	var consumersWg sync.WaitGroup
	for _, consumer := range consumers {
		consumersWg.Add(1)
		go func(c *ingress.Consumer) {
			defer consumersWg.Done()
			c.ConsumeQueue(ctx)
		}(consumer)
	}

	// Start shard discovery monitor if interval is configured
	if cfg.ShardDiscoveryInterval > 0 {
		go monitorShardCount(ctx, cfg, initialShardCount, stop)
	}

	// Wait for termination signal
	<-ctx.Done()
	slog.Info("shutdown signal received")

	// Wait for all consumers to stop
	consumersWg.Wait()
	slog.Info("all consumers stopped")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()

	// Gracefully shutdown health server
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("health server shutdown failed", "error", err)
	}
	slog.Warn("service stopped")
}

func setupHealthChecks(mux *http.ServeMux) {
	// Kubernetes liveness probe
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Kubernetes readiness probe
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})

	// Version info
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"version":   version,
			"commit":    commit,
			"buildDate": buildDate,
		})
	})
}

// monitorShardCount periodically checks if the shard count has changed.
// If a change is detected, it triggers a graceful shutdown so Kubernetes
// can restart the pod with the new configuration.
func monitorShardCount(ctx context.Context, cfg ranger.Config, expectedCount int, triggerShutdown context.CancelFunc) {
	discovery := ingress.NewShardDiscovery(cfg)
	ticker := time.NewTicker(cfg.ShardDiscoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			shardsResp, err := discovery.DiscoverShards(ctx)
			if err != nil {
				slog.Warn("shard discovery check failed", "error", err)
				continue
			}

			if shardsResp.Count != expectedCount {
				slog.Warn("shard count changed, initiating graceful restart",
					"expected", expectedCount,
					"discovered", shardsResp.Count,
				)
				triggerShutdown()
				return
			}

			slog.Debug("shard count unchanged", "count", shardsResp.Count)
		}
	}
}
