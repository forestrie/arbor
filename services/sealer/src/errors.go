package sealer

import "errors"

var (
	// ErrDelegationExpired indicates the current delegated signing certificate is
	// expired or too close to expiry to safely complete a sealing run. The
	// caller should retry after obtaining a fresh delegation.
	ErrDelegationExpired = errors.New("delegation expired or expiring")
	// ErrDelegationPending indicates the issuer has recorded a BYOK delegation
	// request but does not yet have wallet-signed material for it. The caller
	// should keep the message unacked so a later queue delivery can retry.
	ErrDelegationPending = errors.New("delegation material pending")
)
