package sealer

import "errors"

var (
	// ErrDelegationExpired indicates the current delegated signing certificate is
	// expired or too close to expiry to safely complete a sealing run. The
	// caller should retry after obtaining a fresh delegation.
	ErrDelegationExpired = errors.New("delegation expired or expiring")
)
