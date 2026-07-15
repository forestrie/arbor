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
	trustRoot := sealer.NewSelectingTrustRootClient(cfg, httpClient)
	issuer := &sealer.HTTPDelegationIssuer{
		BaseURL:    cfg.DelegationIssuerURL,
		Token:      cfg.DelegationIssuerToken,
		HTTPClient: httpClient,
	}
	leaseMgr := sealer.NewDelegationLeaseManager(trustRoot, issuer, 0, 0)
	leaseMgr.SetRangePad(cfg.DelegationRangePad)
	leaseMgr.SetMaxLeases(cfg.DelegationMaxLeases)
	if cfg.ContractRPCURL != "" {
		if v, err := sealer.NewRPCERC1271Verifier(cfg.ContractRPCURL); err != nil {
			slog.Error("invalid UNIVOCITY_CONTRACT_RPC_URL", "error", err)
			os.Exit(1)
		} else {
			leaseMgr.SetERC1271Verifier(v)
		}
	}
	if cfg.UnivocityAuthorityURL != "" {
		leaseMgr.SetAuthorityResolver(&sealer.HTTPAuthorityResolver{
			BaseURL:    cfg.UnivocityAuthorityURL,
			Token:      cfg.UnivocityAPIToken,
			HTTPClient: httpClient,
		})
		slog.Info("sealer using univocity authority resolver",
			"univocity_authority_url", cfg.UnivocityAuthorityURL,
		)
	}

	slog.Info("sealer configured for per-log delegation",
		"trust_root_url", cfg.TrustRootURL,
		"delegation_issuer_url", cfg.DelegationIssuerURL,
		"delegation_key_curve", cfg.DelegationKeyCurve,
	)
	if cfg.CustodianURL != "" && (cfg.TrustRootURL == cfg.CustodianURL || cfg.DelegationIssuerURL == cfg.CustodianURL) {
		slog.Warn("CUSTODIAN_URL is deprecated; use TRUST_ROOT_URL and DELEGATION_ISSUER_URL")
	}

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

	// Delegation-in-advance (ADR-0050 / plan-2607-20). Off unless
	// DELEGATE_KEY_EPOCH >= 1. When enabled, derive the standing delegate keys
	// (epoch N and N-1) at boot from the custodian-gated seed and route lease
	// issuance through them (Phase D). The custodian is required at boot (no
	// on-demand degrade); StartDelegateKeysWithRetry retries in the background if
	// the custodian is not yet up, so sealer and custodian start in any order
	// (Phase J1). Deterministic re-derivation means a restart re-loads the same
	// keys, so outstanding advance certificates stay valid.
	sealer.StartDelegateKeysWithRetry(ctx, httpClient, logger, cfg, leaseMgr)

	queueConsumer := consumer.NewQueueConsumer(cfg, httpClient, logger, leaseMgr, metricsHandles)
	go queueConsumer.ConsumeQueue(ctx)

	// Level-triggered resync (ADR-0007 phase-3 / plan-2607-04): the correctness
	// backstop to the edge-triggered queue above. Disabled unless
	// RESYNC_MASSIF_HEIGHTS is set; stays strictly pull-only (re-drives seals
	// in-process, never publishes to the queue).
	if resyncMgr, err := sealer.NewResyncManager(cfg, httpClient, logger, leaseMgr, metricsHandles); err != nil {
		slog.Error("failed to build resync manager; resync disabled", "error", err)
	} else {
		go resyncMgr.Run(ctx)
	}

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
