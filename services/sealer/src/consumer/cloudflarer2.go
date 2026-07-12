package consumer

// R2Notification represents the message format from R2 event notifications.
//
// Ranger-published seal hints (ADR-0007 phase 1) reuse this exact shape —
// including Action "PutObject", which the consumer gates on — and additionally
// set HintSource ("ranger_hint") so sealer_seal_trigger_total{source} can
// attribute the wake path. Real R2 event notifications never carry hintSource.
type R2Notification struct {
	Account    string   `json:"account"`
	Action     string   `json:"action"`
	Bucket     string   `json:"bucket"`
	Object     R2Object `json:"object"`
	EventTime  string   `json:"eventTime"`
	HintSource string   `json:"hintSource,omitempty"`
}

// R2Object represents the object information in R2 notifications.
type R2Object struct {
	Key  string `json:"key"`
	Size int64  `json:"size"`
	ETag string `json:"eTag"`
}
