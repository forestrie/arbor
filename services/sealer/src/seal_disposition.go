package sealer

import "errors"

// SealDisposition is what the caller of a failed seal does with the log's
// work.
type SealDisposition int

const (
	// SealFailed: an unexpected failure. The work stays queued and is
	// counted as a failure.
	SealFailed SealDisposition = iota
	// SealDeferred: the log cannot be sealed yet (its authority or its
	// delegation is pending, or the delegation is expiring). The work stays
	// queued for a later attempt.
	SealDeferred
	// SealDropped: the log will never be sealed again (its authority is
	// conflicted). The work is acknowledged and dropped, not retried.
	SealDropped
)

// ClassifySealError says what to do with a log whose seal failed with err,
// and gives a short reason for logs and metrics.
func ClassifySealError(err error) (SealDisposition, string) {
	switch {
	case errors.Is(err, ErrLogConflicted):
		return SealDropped, "conflicted"
	case errors.Is(err, ErrAuthorityPending):
		return SealDeferred, "authority_pending"
	case errors.Is(err, ErrDelegationExpired):
		return SealDeferred, "expired"
	case errors.Is(err, ErrDelegationPending):
		return SealDeferred, "pending"
	default:
		return SealFailed, ""
	}
}
