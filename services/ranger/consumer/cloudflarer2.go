package consumer

// R2Notification represents the message format from R2 event notifications.
type R2Notification struct {
	Account   string   `json:"account"`
	Action    string   `json:"action"`
	Bucket    string   `json:"bucket"`
	Object    R2Object `json:"object"`
	EventTime string   `json:"eventTime"`
}

// R2Object represents the object information in R2 notifications.
type R2Object struct {
	Key  string `json:"key"`
	Size int64  `json:"size"`
	ETag string `json:"eTag"`
}

// ParsedNotification contains extracted data from R2 notification.
type ParsedNotification struct {
	LogID      []byte
	FenceIndex int
	Hash       []byte
	Path       string
	ETag       string
	EventTime  string
}
