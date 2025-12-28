package committer

import (
	"io"
	"log/slog"
	"testing"

	"github.com/forestrie/arbor/services/ranger"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

func TestNewCommitter_Success(t *testing.T) {
	cfg := ranger.Config{
		R2URL:              "https://example.com/bucket",
		AWSAccessKeyID:     "AKIA_TEST",
		AWSSecretAccessKey: "secret",
		AWSRegion:          "auto",
		WorkerCIDR:         "10.0.0.0/24",
		PodIP:              "10.0.0.1",
		CommitmentEpoch:    1,
		MassifHeight:       0,
	}

	httpClient := ranger.NewHTTPClient(newTestLogger())
	defer httpClient.Close()

	c, err := NewCommitter(cfg, httpClient, newTestLogger())
	if err != nil {
		t.Fatalf("NewCommitter: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil committer")
	}
	if c.factory == nil {
		t.Fatal("expected factory to be initialised")
	}
	if c.idState == nil {
		t.Fatal("expected idState to be initialised")
	}
	if c.massifHeight == 0 {
		t.Fatal("expected massifHeight to be defaulted from config")
	}
}
