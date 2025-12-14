package consumer

import "encoding/json"

// QueueMessage represents a message from Cloudflare Queue.
type QueueMessage struct {
	ID          string            `json:"id"`
	TimestampMs int64             `json:"timestamp_ms"`
	Body        json.RawMessage   `json:"body"`
	Attempts    int               `json:"attempts"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	LeaseID     string            `json:"lease_id,omitempty"`
}

// QueuePullResponse represents the pull response from Cloudflare Queue.
type QueuePullResponse struct {
	Success bool            `json:"success"`
	Result  QueuePullResult `json:"result"`
}

// QueuePullResult contains the actual messages and metadata for a pull.
type QueuePullResult struct {
	MessageBacklogCount int            `json:"message_backlog_count"`
	Messages            []QueueMessage `json:"messages"`
}

// QueueAckResponse represents the acknowledgment response from Cloudflare Queue.
type QueueAckResponse struct {
	Success bool `json:"success"`
	Result  struct {
		AckCount   int      `json:"ackCount"`
		RetryCount int      `json:"retryCount"`
		Warnings   []string `json:"warnings"`
	} `json:"result"`
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}
