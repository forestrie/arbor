package ingress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/logredact"
	"github.com/forestrie/arbor/services/ranger"
)

// ShardInfo contains information about a single shard.
type ShardInfo struct {
	Index        int `json:"index"`
	PendingCount int `json:"pendingCount"`
}

// ShardsResponse is the response from GET /queue/shards.
type ShardsResponse struct {
	Count           int         `json:"count"`
	PullURLTemplate string      `json:"pullUrlTemplate"`
	AckURLTemplate  string      `json:"ackUrlTemplate"`
	Shards          []ShardInfo `json:"shards"`
}

// ShardDiscovery handles shard discovery for the ingress queue.
type ShardDiscovery struct {
	cfg        ranger.Config
	httpClient *http.Client
}

// NewShardDiscovery creates a new shard discovery client.
func NewShardDiscovery(cfg ranger.Config) *ShardDiscovery {
	return &ShardDiscovery{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// DiscoverShards queries the shard discovery endpoint and returns shard information.
func (d *ShardDiscovery) DiscoverShards(ctx context.Context) (*ShardsResponse, error) {
	url := strings.TrimSuffix(d.cfg.QueueURL, "/") + "/queue/shards"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create discovery request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+d.cfg.QueueToken)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("discovery returned status %d: body_sha256=%s", resp.StatusCode, logredact.SHA256Hex(body))
	}

	var shardsResp ShardsResponse
	if err := json.NewDecoder(resp.Body).Decode(&shardsResp); err != nil {
		return nil, fmt.Errorf("decode discovery response: %w", err)
	}

	return &shardsResp, nil
}

// BuildPullURL constructs the pull URL for a specific shard.
func (d *ShardDiscovery) BuildPullURL(shardIndex int) string {
	baseURL := strings.TrimSuffix(d.cfg.QueueURL, "/")
	return fmt.Sprintf("%s/queue/pull?shard=%d", baseURL, shardIndex)
}

// BuildAckURL constructs the ack URL for a specific shard.
func (d *ShardDiscovery) BuildAckURL(shardIndex int) string {
	baseURL := strings.TrimSuffix(d.cfg.QueueURL, "/")
	return fmt.Sprintf("%s/queue/ack?shard=%d", baseURL, shardIndex)
}
