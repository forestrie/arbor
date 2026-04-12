package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/forestrie/arbor/services/sealer"
	"github.com/forestrie/arbor/services/sealer/consumer"
	"github.com/forestrie/arbor/services/sealer/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	version   string
	commit    string
	buildDate string
)

func main() {
	cfg := sealer.LoadConfig()
	level, recognized := sealer.ParseLogLevel(cfg.LogLevel)
	logger, _ := sealer.NewLogger(level)

	if !recognized {
		logger.Warn(
			"unrecognized log level value; defaulting to derived level",
			"input", cfg.LogLevel,
			"level", level.String(),
		)
	}

	slog.SetDefault(logger)
	slog.Warn("starting sealer service",
		"version", version,
		"commit", commit,
		"buildDate", buildDate,
	)
	logger.Warn("resolved log level", "input", cfg.LogLevel, "level", level.String())
	cfg.LogConfig(logger)

	if err := cfg.Validate(); err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer stop()

	httpClient := sealer.NewHTTPClient(logger)
	leaseMgr := sealer.NewDelegationLeaseManager(0, 0)

	// Log Custodian configuration (per-log delegation leases are obtained lazily)
	slog.Info("sealer configured for per-log delegation via Custodian",
		"custodian_url", cfg.CustodianURL,
		"delegation_key_curve", cfg.DelegationKeyCurve,
	)

	// Create metrics registry and metrics
	metricsRegistry := prometheus.NewRegistry()
	metricsHandles := metrics.NewMetrics(metricsRegistry)

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

	queueConsumer := consumer.NewQueueConsumer(cfg, httpClient, logger, leaseMgr, metricsHandles)
	go queueConsumer.ConsumeQueue(ctx)

	<-ctx.Done()
	slog.Info("shutdown signal received")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()

	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("health server shutdown failed", "error", err)
	}
	slog.Warn("service stopped")
}

func setupHealthChecks(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"version":   version,
			"commit":    commit,
			"buildDate": buildDate,
		})
	})
}
