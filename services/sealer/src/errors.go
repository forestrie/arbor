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
	// ErrNoStandingDelegateKeys indicates a lease was requested before the
	// standing delegate keys were installed. The sealer consumes only once
	// they are, so this is a wiring error, never a cue to fall back
	// (devdocs plan-2609-12 slice 10).
	ErrNoStandingDelegateKeys = errors.New("no standing delegate keys installed")
	// ErrOnchainProofRangeMismatch indicates the issuer's on-chain delegation
	// proof signs a different MMR range from the delegation certificate.
	// Univocity checks the proof at publication and offline verification
	// checks the certificate, so the two ranges must be equal or a
	// checkpoint can publish on-chain yet fail offline verification.
	ErrOnchainProofRangeMismatch = errors.New("on-chain delegation proof range does not match certificate range")
)
