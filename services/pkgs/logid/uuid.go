package logid

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Size is the byte length of a semantic log id UUID.
const Size = 16

// UUID is a 16-byte Forestrie log identifier.
type UUID [Size]byte

var (
	ErrInvalidUUID     = errors.New("invalid log id uuid")
	ErrInvalidSegment  = errors.New("invalid log id path segment")
	ErrAmbiguousLength = errors.New("log id segment must be uuid or 32 hex chars, not 64")
)

// Zero is the nil UUID.
var Zero UUID

// IsZero reports whether u is unset.
func (u UUID) IsZero() bool { return u == Zero }

// String returns the canonical dashed UUID form.
func (u UUID) String() string {
	b := u[:]
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]),
		uint16(b[4])<<8|uint16(b[5]),
		uint16(b[6])<<8|uint16(b[7]),
		uint16(b[8])<<8|uint16(b[9]),
		uint64(b[10])<<40|uint64(b[11])<<32|uint64(b[12])<<24|uint64(b[13])<<16|uint64(b[14])<<8|uint64(b[15]),
	)
}

// ParseUUIDString parses a canonical or hyphenless UUID string.
func ParseUUIDString(s string) (UUID, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return Zero, ErrInvalidUUID
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != Size {
		return Zero, ErrInvalidUUID
	}
	var out UUID
	copy(out[:], raw)
	return out, nil
}

// ParseCanonicalSegment parses a dashed UUID HTTP/R2 path segment only.
// Hyphenless 32-hex and 64-char padded wire hex are rejected.
func ParseCanonicalSegment(s string) (UUID, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Zero, ErrInvalidSegment
	}
	if !strings.Contains(s, "-") {
		return Zero, ErrInvalidSegment
	}
	return ParseUUIDString(s)
}

// ParseSegment parses an HTTP or R2 path segment: canonical UUID or 32-char hex.
// 64-char padded wire hex is rejected.
func ParseSegment(s string) (UUID, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Zero, ErrInvalidSegment
	}
	compact := strings.ReplaceAll(strings.TrimPrefix(strings.ToLower(s), "0x"), "-", "")
	switch len(compact) {
	case 32:
		return ParseUUIDString(compact)
	case 64:
		return Zero, ErrAmbiguousLength
	default:
		return Zero, ErrInvalidSegment
	}
}

// FromHex32 parses a 32-character lowercase hex string (custodian KMS style).
func FromHex32(s string) (UUID, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 32 {
		return Zero, ErrInvalidUUID
	}
	return ParseUUIDString(s)
}

// FromBytes accepts exactly 16 raw UUID bytes or 32-byte right-padded wire form.
func FromBytes(b []byte) (UUID, error) {
	switch len(b) {
	case Size:
		var out UUID
		copy(out[:], b)
		return out, nil
	case 32:
		return FromPaddedWire32(b), nil
	default:
		return Zero, fmt.Errorf("%w: got %d bytes", ErrInvalidUUID, len(b))
	}
}

// FromContractBytes32 decodes an on-chain bytes32 log id (UUID right-aligned).
func FromContractBytes32(b [32]byte) UUID {
	var out UUID
	copy(out[:], b[16:])
	return out
}

// ToContractBytes32 encodes a UUID as on-chain bytes32 (left-padded with zeros).
func (u UUID) ToContractBytes32() [32]byte {
	var out [32]byte
	copy(out[16:], u[:])
	return out
}

// FromPaddedWire32 decodes grant/genesis CBOR 32-byte padded wire form.
func FromPaddedWire32(wire []byte) UUID {
	var out UUID
	if len(wire) == 32 {
		copy(out[:], wire[16:])
	} else if len(wire) == Size {
		copy(out[:], wire)
	}
	return out
}

// ToPaddedWire32 encodes a UUID as grant/genesis CBOR 32-byte padded wire form.
func (u UUID) ToPaddedWire32() [32]byte {
	var out [32]byte
	copy(out[16:], u[:])
	return out
}

// ParseIndexBody parses an index object body (ASCII canonical UUID of R).
func ParseIndexBody(body []byte) (UUID, error) {
	return ParseUUIDString(strings.TrimSpace(string(body)))
}
