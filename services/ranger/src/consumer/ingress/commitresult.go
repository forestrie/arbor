package ingress

// CommitResult contains metadata from a successful batch commit.
// Used to populate the ack request with sequencing information.
type CommitResult struct {
	// Number of entries successfully committed
	Committed int
	// Leaf index of the first entry in the committed batch
	FirstLeafIndex uint64
	// R2 object keys of the massifs written by this commit, in write order
	// (a batch that rolls over a massif boundary writes more than one).
	// Consumed by the seal-hint publisher after ack (ADR-0007 phase 1).
	MassifObjectKeys []string
}
