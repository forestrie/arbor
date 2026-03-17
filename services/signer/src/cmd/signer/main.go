package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"

	"github.com/forestrie/arbor/services/signer"
)

var (
	version   string
	commit    string
	buildDate string
)

func main() {
	cfg := signer.LoadConfig()
	level, recognized := signer.ParseLogLevel(cfg.LogLevel)
	logger, _ := signer.NewLogger(level)

	if !recognized {
		logger.Warn("unrecognized log level; defaulting to derived level", "input", cfg.LogLevel, "level", level.String())
	}

	slog.SetDefault(logger)
	slog.Info("starting signer service (Plan 0004 subplan 04)",
		"version", version,
		"commit", commit,
		"buildDate", buildDate,
	)
	cfg.LogConfig(logger)

	if cfg.BootstrapKeyID == "" {
		slog.Error("SIGNER_BOOTSTRAP_KEY_ID is required")
		os.Exit(1)
	}

	ctx := context.Background()
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		slog.Error("failed to create KMS client", "error", err)
		os.Exit(1)
	}
	defer kmsClient.Close()

	// Wrap *kms.KeyManagementClient so it matches KeyManagementClient interface (AsymmetricSign).
	keySigner := signer.NewGCPKeySigner(&kmsClientAdapter{client: kmsClient})
	parentResolver := signer.NewParentResolver(cfg)

	api := &signer.API{
		Logger:         logger,
		KeySigner:      keySigner,
		BootstrapKeyID: cfg.BootstrapKeyID,
		ParentResolver: parentResolver,
	}

	mux := http.NewServeMux()
	setupHealthChecks(mux)
	api.RegisterRoutes(mux)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: mux,
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		slog.Info("HTTP server listening", "port", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server failed", "error", err)
		}
	}()

	<-sigCtx.Done()
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
		_ = signer.EncodeVersion(w, version, commit, buildDate)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("# signer metrics stub\n"))
	})
}

// kmsClientAdapter adapts *kms.KeyManagementClient to KeyManagementClient interface.
type kmsClientAdapter struct {
	client *kms.KeyManagementClient
}

func (a *kmsClientAdapter) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...interface{}) (*kmspb.AsymmetricSignResponse, error) {
	return a.client.AsymmetricSign(ctx, req)
}
