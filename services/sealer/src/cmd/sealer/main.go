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

	"github.com/forestrie/arbor/services/sealer"
	"github.com/forestrie/arbor/services/sealer/consumer"
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

	// Startup check: ensure we can obtain an impersonated access token for the
	// delegation-signer service account. Fail fast to avoid running without the
	// required trust boundary plumbing.
	startupCtx, startupCancel := context.WithTimeout(ctx, 20*time.Second)
	defer startupCancel()
	token, err := sealer.AcquireDelegationSignerAccessToken(startupCtx, cfg.DelegationSignerServiceAccountEmail)
	if err != nil {
		slog.Error("failed to obtain delegation signer access token",
			"target_service_account", cfg.DelegationSignerServiceAccountEmail,
			"error", err,
		)
		os.Exit(1)
	}
	slog.Info("obtained delegation signer access token",
		"target_service_account", token.Info.TargetServiceAccount,
		"token_type", token.Info.TokenType,
		"expiry", token.Info.Expiry,
		"expires_in", token.Info.ExpiresIn.String(),
		"token_len", token.Info.TokenLength,
		"token_fingerprint", token.Info.TokenFingerprint,
	)

	httpClient := sealer.NewHTTPClient(logger)

	leaseMgr := sealer.NewDelegationLeaseManager(0, 0)

	// Startup check: obtain (and cache) a global time-limited delegation lease.
	lease, err := leaseMgr.EnsureValid(
		startupCtx,
		httpClient,
		logger,
		cfg.DelegationSignerURL,
		token.AccessToken,
		cfg.DelegationKeyCurve,
	)
	if err != nil {
		slog.Error("failed to obtain delegation lease",
			"delegation_signer_url", cfg.DelegationSignerURL,
			"curve", cfg.DelegationKeyCurve,
			"error", err,
		)
		os.Exit(1)
	}
	slog.Info("obtained delegation lease",
		"cert_sha256", lease.Info.CertSHA256,
		"cert_size", lease.Info.CertSize,
		"alg", lease.Info.ProtectedAlg,
		"cty", lease.Info.ProtectedCty,
		"kid_hex", lease.Info.ProtectedKidHex,
		"issued_at", lease.IssuedAt,
		"expires_at", lease.ExpiresAt,
		"delegated_curve", lease.Info.PayloadDelegatedCurve,
		"signature_size", lease.Info.SignatureSize,
	)

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

	queueConsumer := consumer.NewQueueConsumer(cfg, httpClient, logger, leaseMgr)
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
