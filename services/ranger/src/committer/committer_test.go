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

func TestNewR2Committer_Success(t *testing.T) {
	cfg := ranger.Config{
		R2WriteURL:      "https://example.com/bucket",
		R2WriterToken:   "token",
		WorkerCIDR:      "10.0.0.0/24",
		PodIP:           "10.0.0.1",
		CommitmentEpoch: 1,
		MassifHeight:    0,
		TrustCanopy:     true,
	}

	httpClient := ranger.NewHTTPClient(newTestLogger())
	defer httpClient.Close()

	c, err := NewR2Committer(cfg, httpClient, newTestLogger())
	if err != nil {
		t.Fatalf("NewR2Committer: %v", err)
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
	if !c.trustCanopy {
		t.Fatal("expected trustCanopy to be propagated from config")
	}
}