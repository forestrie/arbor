package ingress

// PullRequest is sent to POST /queue/pull.
type PullRequest struct {
	PollerId     string `cbor:"pollerId"`
	BatchSize    int    `cbor:"batchSize"`
	VisibilityMs int    `cbor:"visibilityMs"`
}

// EncodePullRequest encodes a pull request to CBOR.
func EncodePullRequest(req PullRequest) ([]byte, error) {
	return canonicalCBOR.Marshal(req)
}
