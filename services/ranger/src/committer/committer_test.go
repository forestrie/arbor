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
		MassifHeight:       14,
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
	if c.massifHeight != 14 {
		t.Fatalf("massifHeight = %d, want the configured 14", c.massifHeight)
	}
}

// TestNewCommitter_RejectsZeroMassifHeight: the consumer acks with
// cfg.MassifHeight, so a committer that silently wrote at another height
// would ack a height it never used.
func TestNewCommitter_RejectsZeroMassifHeight(t *testing.T) {
	cfg := ranger.Config{
		R2URL:              "https://example.com/bucket",
		AWSAccessKeyID:     "AKIA_TEST",
		AWSSecretAccessKey: "secret",
		AWSRegion:          "auto",
		WorkerCIDR:         "10.0.0.0/24",
		PodIP:              "10.0.0.1",
		CommitmentEpoch:    1,
	}
	httpClient := ranger.NewHTTPClient(newTestLogger())
	defer httpClient.Close()

	if _, err := NewCommitter(cfg, httpClient, newTestLogger()); err == nil {
		t.Fatal("NewCommitter accepted MassifHeight 0")
	}
}
