package sealer

import (
	"errors"
	"testing"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// A cached lease for [0,1] must not be reused for a later seal [0,3]: the
// on-chain proof binds mmrEnd in the root signature, and univocity reverts
// CheckpointIndexOutOfDelegationRange when claimedSize-1 > mmrEnd.
func TestLeaseCoversMMRRange_OnchainProof(t *testing.T) {
	lease := &DelegationLease{
		OnchainProof: &delegationcert.OnchainDelegationProof{
			MMRStart: 0,
			MMREnd:   1,
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if !leaseCoversMMRRange(lease, 0, 1) {
		t.Fatal("expected [0,1] to cover [0,1]")
	}
	if !leaseCoversMMRRange(lease, 1, 1) {
		t.Fatal("expected [0,1] to cover [1,1]")
	}
	if leaseCoversMMRRange(lease, 0, 3) {
		t.Fatal("expected [0,1] not to cover [0,3]")
	}
}

func TestLeaseCoversMMRRange_OnchainProofInterior(t *testing.T) {
	lease := &DelegationLease{
		OnchainProof: &delegationcert.OnchainDelegationProof{
			MMRStart: 0,
			MMREnd:   3,
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if !leaseCoversMMRRange(lease, 1, 1) {
		t.Fatal("expected [0,3] to cover [1,1]")
	}
	if !leaseCoversMMRRange(lease, 0, 3) {
		t.Fatal("expected [0,3] to cover [0,3]")
	}
}

func TestEnsureValidForLog_RejectsCachedLeaseOutsideRange(t *testing.T) {
	logID := "abcdef0123456789abcdef0123456789"
	mgr := NewDelegationLeaseManager(
		&stubTrustRootClient{},
		&pendingIssuerStub{},
		time.Hour,
		time.Minute,
	)
	lease := &DelegationLease{
		OnchainProof: &delegationcert.OnchainDelegationProof{
			MMRStart: 0,
			MMREnd:   1,
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	entry := &leaseEntry{key: logID, lease: lease}
	elem := mgr.lru.PushFront(entry)
	mgr.leases[logID] = elem

	// Request for [0,3] must not return the cached [0,1] lease; with the
	// pending issuer stub it surfaces ErrDelegationPending after eviction.
	_, err := mgr.EnsureValidForLog(
		t.Context(),
		NewHTTPClient(nil),
		nil,
		"secp256r1",
		logID,
		0,
		3,
	)
	if !errors.Is(err, ErrDelegationPending) {
		t.Fatalf("got %v want ErrDelegationPending (cached lease must be evicted)", err)
	}
	if _, ok := mgr.leases[logID]; ok {
		t.Fatal("expected non-covering cached lease to be evicted")
	}
}
