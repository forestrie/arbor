package ingress

// CommitResult contains metadata from a successful batch commit.
// Used to populate the ack request with sequencing information.
type CommitResult struct {
	// Number of entries successfully committed
	Committed int
	// Leaf index of the first entry in the committed batch
	FirstLeafIndex uint64
}
