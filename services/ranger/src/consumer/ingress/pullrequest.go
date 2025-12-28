package ingress

import "github.com/fxamacker/cbor/v2"

// PullRequest is sent to POST /queue/pull.
type PullRequest struct {
	PollerId     string `cbor:"pollerId"`
	BatchSize    int    `cbor:"batchSize"`
	VisibilityMs int    `cbor:"visibilityMs"`
}

// EncodePullRequest encodes a pull request to CBOR.
func EncodePullRequest(req PullRequest) ([]byte, error) {
	return cbor.Marshal(req)
}
