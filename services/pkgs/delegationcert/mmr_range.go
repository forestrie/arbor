package delegationcert

import (
	"errors"
	"fmt"
)

// Errors for the delegation's MMR range (payload labels 3 and 4) and the
// log id it is scoped to. The builder rejects what ParseCertificate would
// reject, so a certificate the builder emits is one the parser accepts:
// ErrMMRRangeInverted is returned by both, ErrMMRRangeBound only by the
// parser, ErrLogIDRequired only by the builder.
var (
	// ErrMMRRangeBound reports a range bound that is missing or is not a
	// CBOR unsigned integer. An absent bound must not read as 0, and a
	// float is not an index, even a whole-number one.
	ErrMMRRangeBound = errors.New("mmr range bound is missing or not an unsigned integer")

	// ErrMMRRangeInverted reports a range whose start is past its end.
	// The range is inclusive, so start == end is one index and is valid.
	ErrMMRRangeInverted = errors.New("mmr range is inverted")

	// ErrLogIDRequired reports a delegation built without a log id. The
	// range labels are written only alongside the log id they index into,
	// so a certificate without one would carry no range.
	ErrLogIDRequired = errors.New("delegation log id is required")
)

// ValidateMMRRange checks the inclusive range [start, end] is not inverted.
// Callers that issue certificates use it to reject a bad request before any
// signing work.
func ValidateMMRRange(start, end uint64) error {
	if start > end {
		return fmt.Errorf("%w: start %d > end %d", ErrMMRRangeInverted, start, end)
	}
	return nil
}
