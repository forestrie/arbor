package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/forestrie/arbor/services/ranger"
	"github.com/forestrie/arbor/services/ranger/committer"
	"github.com/forestrie/arbor/services/ranger/consumer"
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

	// Create HTTP client with persistent connections for queue operations
	httpClient := ranger.NewHTTPClient(logger)

	// Create committer wired to the S3-compatible backend (Cloudflare R2 compatible)
	massifCommitter, err := committer.NewCommitter(cfg, httpClient, logger)
	if err != nil {
		slog.Error("failed to create committer", "error", err)
		os.Exit(1)
	}
	slog.Info("merklelog committer initialized",
		"massifHeight", cfg.MassifHeight,
		"commitmentEpoch", cfg.CommitmentEpoch,
	)

	// Start health check server
	healthMux := http.NewServeMux()
	setupHealthChecks(healthMux)

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

	// Start queue consumer
	queueConsumer := consumer.NewQueueConsumer(cfg, httpClient, logger, massifCommitter)
	go queueConsumer.ConsumeQueue(ctx)

	// Wait for termination signal
	<-ctx.Done()
	slog.Info("shutdown signal received")

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
