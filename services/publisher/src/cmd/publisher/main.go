// Command publisher anchors sealed v3 checkpoints on-chain. With no subcommand
// it runs as a Cloudflare-queue daemon; the `publish` subcommand runs the
// one-shot core against a single checkpoint key (for system-testing before the
// GitOps rollout completes).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/forestrie/arbor/services/publisher"
	"github.com/forestrie/arbor/services/publisher/consumer"
	"github.com/forestrie/arbor/services/publisher/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	version   string
	commit    string
	buildDate string
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "publish" {
		os.Exit(runPublish(os.Args[2:]))
	}
	runDaemon()
}

// runPublish is the one-shot CLI: `publisher publish --key <checkpointObjectKey>`.
func runPublish(argv []string) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	key := fs.String("key", "", "checkpoint object key (v2/merklelog/checkpoints/{h}/{uuid}/{index}.sth)")
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *key == "" {
		fmt.Fprintln(os.Stderr, "publish: --key is required")
		return 2
	}

	cfg := publisher.LoadConfig()
	level, _ := publisher.ParseLogLevel(cfg.LogLevel)
	logger, _ := publisher.NewLogger(level)
	slog.SetDefault(logger)
	if err := cfg.ValidateCLI(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	httpClient := publisher.NewHTTPClient(logger)
	defer httpClient.Close()
	pub, err := publisher.NewPublisher(cfg, httpClient, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init publisher: %v\n", err)
		return 1
	}
	defer pub.Close()

	res, err := pub.Publish(ctx, *key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "publish: %v\n", err)
		return 1
	}

	if *asJSON {
		out := map[string]any{
			"status": res.Status.String(), "key": res.Key,
			"chainId": res.ChainID, "contract": res.Contract.Hex(),
			"tx": res.TxHash.Hex(), "sealedSize": res.SealedSize,
			"onchainSize": res.OnchainSize, "reason": res.Reason,
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
	} else {
		fmt.Printf("status=%s chain=%d contract=%s tx=%s sealed=%d onchain=%d %s\n",
			res.Status, res.ChainID, res.Contract.Hex(), res.TxHash.Hex(),
			res.SealedSize, res.OnchainSize, res.Reason)
	}

	// Terminal-failure statuses map to a non-zero exit so callers can gate.
	switch res.Status {
	case publisher.StatusPublished, publisher.StatusAlreadyAnchored:
		return 0
	default:
		return 3
	}
}

// runDaemon runs the queue-consuming service.
func runDaemon() {
	cfg := publisher.LoadConfig()
	level, recognized := publisher.ParseLogLevel(cfg.LogLevel)
	logger, _ := publisher.NewLogger(level)
	slog.SetDefault(logger)
	if !recognized {
		logger.Warn("unrecognized log level; using derived", "input", cfg.LogLevel, "level", level.String())
	}
	slog.Warn("starting publisher service", "version", version, "commit", commit, "buildDate", buildDate)
	cfg.LogConfig(logger)

	if err := cfg.Validate(); err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	httpClient := publisher.NewHTTPClient(logger)
	pub, err := publisher.NewPublisher(cfg, httpClient, logger)
	if err != nil {
		slog.Error("init publisher", "error", err)
		os.Exit(1)
	}
	defer pub.Close()
	slog.Info("publisher configured", "eoa", pub.From().Hex(), "chains", len(cfg.RPCURLs))

	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)

	mux := http.NewServeMux()
	setupHealthChecks(mux)
	mux.Handle("/metrics", metrics.Handler(reg))
	healthServer := &http.Server{Addr: ":" + cfg.Port, Handler: mux}
	go func() {
		slog.Warn("starting health check server", "port", cfg.Port)
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("health server failed", "error", err)
		}
	}()

	qc := consumer.NewQueueConsumer(cfg, httpClient, logger, pub, m)
	go qc.ConsumeQueue(ctx)

	<-ctx.Done()
	slog.Info("shutdown signal received")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
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
		_ = json.NewEncoder(w).Encode(map[string]string{"version": version, "commit": commit, "buildDate": buildDate})
	})
}
