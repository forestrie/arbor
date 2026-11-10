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
	// ErrAuthorityPending indicates univocity has not anchored the log's
	// authority, or an ancestor's, so its root key may not be used yet
	// (protocol ADR-0070). The caller retries later and never looks for the
	// key anywhere else.
	ErrAuthorityPending = errors.New("log authority pending")
	// ErrLogConflicted indicates univocity found that the chain recorded a
	// different owner or key at the log's first checkpoint than its claim
	// (devdocs ADR-0075 decision 8). Final: the log is not sealed again, and
	// its queued work is dropped rather than retried.
	ErrLogConflicted = errors.New("log authority conflicted")
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
