package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/forestrie/arbor/services/univocity"
)

var (
	version   string
	commit    string
	buildDate string
)

func main() {
	cfg := univocity.LoadConfig()
	level, recognized := univocity.ParseLogLevel(cfg.LogLevel)
	logger, _ := univocity.NewLogger(level)

	if !recognized {
		logger.Warn(
			"unrecognized log level value; defaulting to derived level",
			"input", cfg.LogLevel,
			"level", level.String(),
		)
	}

	slog.SetDefault(logger)
	slog.Info("starting univocity auth-log status service",
		"version", version,
		"commit", commit,
		"buildDate", buildDate,
	)
	logger.Info("resolved log level", "input", cfg.LogLevel, "level", level.String())
	cfg.LogConfig(logger)

	if cfg.UnivocityRPCURL == "" || cfg.UnivocityContractAddress == "" {
		slog.Error("UNIVOCITY_RPC_URL and UNIVOCITY_CONTRACT_ADDRESS are required")
		os.Exit(1)
	}

	chain, err := univocity.NewUnivocityContract(cfg.UnivocityRPCURL, cfg.UnivocityContractAddress)
	if err != nil {
		slog.Error("failed to connect to univocity contract", "error", err)
		os.Exit(1)
	}
	defer chain.Close()

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer stop()

	mux := http.NewServeMux()
	setupHealthChecks(mux)

	api := univocity.API{Logger: logger, Chain: chain}
	api.RegisterRoutes(mux)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: mux,
	}

	go func() {
		slog.Info("HTTP server listening", "port", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server failed", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP server shutdown failed", "error", err)
	}
	slog.Info("service stopped")
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
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("# univocity metrics stub\n"))
	})
}
