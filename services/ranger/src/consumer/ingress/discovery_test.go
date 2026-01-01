package ingress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forestrie/arbor/services/ranger"
)

func TestShardDiscovery_DiscoverShards(t *testing.T) {
	expected := ShardsResponse{
		Count:           4,
		PullURLTemplate: "/queue/pull?shard={shard}",
		AckURLTemplate:  "/queue/ack?shard={shard}",
		Shards: []ShardInfo{
			{Index: 0, PendingCount: 10},
			{Index: 1, PendingCount: 5},
			{Index: 2, PendingCount: 0},
			{Index: 3, PendingCount: 25},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/queue/shards" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing or invalid Authorization header")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	}))
	defer server.Close()

	cfg := ranger.Config{
		QueueURL:   server.URL,
		QueueToken: "test-token",
	}

	discovery := NewShardDiscovery(cfg)
	ctx := context.Background()

	resp, err := discovery.DiscoverShards(ctx)
	if err != nil {
		t.Fatalf("DiscoverShards: %v", err)
	}

	if resp.Count != expected.Count {
		t.Errorf("Count: got %d, want %d", resp.Count, expected.Count)
	}
	if resp.PullURLTemplate != expected.PullURLTemplate {
		t.Errorf("PullURLTemplate: got %s, want %s", resp.PullURLTemplate, expected.PullURLTemplate)
	}
	if resp.AckURLTemplate != expected.AckURLTemplate {
		t.Errorf("AckURLTemplate: got %s, want %s", resp.AckURLTemplate, expected.AckURLTemplate)
	}
	if len(resp.Shards) != len(expected.Shards) {
		t.Fatalf("Shards length: got %d, want %d", len(resp.Shards), len(expected.Shards))
	}

	for i, shard := range resp.Shards {
		if shard.Index != expected.Shards[i].Index {
			t.Errorf("Shards[%d].Index: got %d, want %d", i, shard.Index, expected.Shards[i].Index)
		}
		if shard.PendingCount != expected.Shards[i].PendingCount {
			t.Errorf("Shards[%d].PendingCount: got %d, want %d", i, shard.PendingCount, expected.Shards[i].PendingCount)
		}
	}
}

func TestShardDiscovery_DiscoverShards_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := ranger.Config{
		QueueURL:   server.URL,
		QueueToken: "test-token",
	}

	discovery := NewShardDiscovery(cfg)
	ctx := context.Background()

	_, err := discovery.DiscoverShards(ctx)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestShardDiscovery_BuildURLs(t *testing.T) {
	cfg := ranger.Config{
		QueueURL:   "https://example.com/api",
		QueueToken: "test-token",
	}

	discovery := NewShardDiscovery(cfg)

	tests := []struct {
		shardIndex int
		wantPull   string
		wantAck    string
	}{
		{0, "https://example.com/api/queue/pull?shard=0", "https://example.com/api/queue/ack?shard=0"},
		{1, "https://example.com/api/queue/pull?shard=1", "https://example.com/api/queue/ack?shard=1"},
		{99, "https://example.com/api/queue/pull?shard=99", "https://example.com/api/queue/ack?shard=99"},
	}

	for _, tt := range tests {
		gotPull := discovery.BuildPullURL(tt.shardIndex)
		if gotPull != tt.wantPull {
			t.Errorf("BuildPullURL(%d): got %s, want %s", tt.shardIndex, gotPull, tt.wantPull)
		}

		gotAck := discovery.BuildAckURL(tt.shardIndex)
		if gotAck != tt.wantAck {
			t.Errorf("BuildAckURL(%d): got %s, want %s", tt.shardIndex, gotAck, tt.wantAck)
		}
	}
}

func TestShardDiscovery_BuildURLs_TrailingSlash(t *testing.T) {
	cfg := ranger.Config{
		QueueURL:   "https://example.com/api/",
		QueueToken: "test-token",
	}

	discovery := NewShardDiscovery(cfg)

	gotPull := discovery.BuildPullURL(0)
	wantPull := "https://example.com/api/queue/pull?shard=0"
	if gotPull != wantPull {
		t.Errorf("BuildPullURL with trailing slash: got %s, want %s", gotPull, wantPull)
	}
}
