package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	"github.com/forestrie/arbor/services/univocity"
)

var (
	version   string
	commit    string
	buildDate string
)

type stdHTTPDoer struct {
	client *http.Client
}

func (d stdHTTPDoer) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return d.client.Do(req.WithContext(ctx))
}

func main() {
	cfg, err := univocity.LoadConfig()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
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
	slog.Info("starting univocity trust-root service",
		"version", version,
		"commit", commit,
		"buildDate", buildDate,
	)
	logger.Info("resolved log level", "input", cfg.LogLevel, "level", level.String())
	cfg.LogConfig(logger)

	pool, err := univocity.NewContractClients(cfg.RPCURLs)
	if err != nil {
		slog.Error("failed to build RPC client pool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	httpClient := &http.Client{Timeout: 60 * time.Second}
	s3Client, err := s3.NewClientWithCredentials(
		cfg.GenesisR2URL,
		cfg.GenesisR2Token,
		cfg.AWSAccessKeyID,
		cfg.AWSSecretAccessKey,
		cfg.AWSRegion,
		stdHTTPDoer{client: httpClient},
		logger,
	)
	if err != nil {
		slog.Error("failed to create genesis R2 client", "error", err)
		os.Exit(1)
	}

	registry := univocity.NewForestRegistry(
		logger, s3Client, cfg.RPCURLs, cfg.GenesisScanMinInterval,
	)
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer stop()

	if err := registry.Scan(ctx); err != nil {
		slog.Error("startup genesis registry scan failed", "error", err)
		os.Exit(1)
	}

	forestResolver := univocity.NewForestResolver(
		logger,
		registry,
		pool,
		cfg.LogForestCacheSize,
		cfg.GenesisScanMinInterval,
	)

	mux := http.NewServeMux()
	setupHealthChecks(mux)

	api := univocity.API{
		Logger:                 logger,
		Pool:                   pool,
		Resolver:               forestResolver,
		Store:                  univocity.NewS3Store(s3Client),
		APIToken:               cfg.APIToken,
		AdminToken:             cfg.AdminToken,
		AllowUnanchoredGenesis: cfg.AllowUnanchoredGenesis,
		Bootstrap:              univocity.NewBootstrapCache(),
	}
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
