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

	// R2Notification is the decoded R2 bucket notification informing of the
	// newly injested leaf object. R2Notification is associative with Messages
	R2Notification []R2Notification

	// Decoded is associative with Messages and is the result of decoding the
	// notification message. Any message that did not decode succcessfully will have an err in
	// the associated Errs entry and the Ack value will be true. It is assumed
	// that any message on the queue is intended from *some* ranger version and
	// will at least decode correctly. Conuming it will not accidentally consume
	// a message intended for a different service.
	Decoded []ProcessedNotification

	// ByLogID contains an index into Messages for each message ordered by LogID
	ByLogID []int

	// Errs has an entry for each processed Message. if it is non nill after
	// processing the log batch, an error prevented the addition of the message'success
	// leaf content to the ledger. Errs is in the same order as Messages and can be indexed
	// indirectly via ByLogID
	Errs []error
	// Ack has a boolean for each Message. All True entries have been either
	// added to the log or have been consumed. Any message that has an Ack of
	// false will be associated with a non nil err
	Ack []bool
}
