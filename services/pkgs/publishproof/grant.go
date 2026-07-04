// Package publishproof builds univocity publishCheckpoint submissions from
// public R2 merklelog objects: consistency proof chains, grant leaf
// commitments, calldata encoding, and on-chain logState reads.
package publishproof

import (
	"fmt"
	"math/big"

	"github.com/forestrie/go-univocity/grant"
)

// PublishGrant mirrors the univocity PublishGrant calldata tuple. LogId and
// OwnerLogId are the contract's bytes32 fields; 16-byte log UUIDs occupy the
// low 16 bytes. Request is not part of the leaf commitment.
type PublishGrant struct {
	LogId      [32]byte
	Grant      *big.Int
	Request    *big.Int
	MaxHeight  uint64
	MinGrowth  uint64
	OwnerLogId [32]byte
	GrantData  []byte
}

// LeafCommitment returns the authority log leaf hash for the grant per
// univocity LibLogState._leafCommitment:
//
//	sha256(idTimestampBe || sha256(logId || grant || maxHeight || minGrowth || ownerLogId || grantData))
//
// The grant flags bitmap must fit the canonical 8-byte flags field (the
// contract's uint256 high bytes are zero for all defined GF_* flags).
func (g PublishGrant) LeafCommitment(idTimestampBe [8]byte) ([32]byte, error) {
	if g.Grant == nil || g.Grant.Sign() < 0 || g.Grant.BitLen() > 64 {
		return [32]byte{}, fmt.Errorf("grant flags must be a non-negative value fitting %d bytes", grant.GrantFlagsBytes)
	}
	var flags [grant.GrantFlagsBytes]byte
	g.Grant.FillBytes(flags[:])
	return grant.LeafCommitment(
		idTimestampBe,
		g.LogId[:],
		flags[:],
		g.MaxHeight,
		g.MinGrowth,
		g.OwnerLogId[:],
		g.GrantData,
	), nil
}
