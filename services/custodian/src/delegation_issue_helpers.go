package custodian

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// logIDHexFromWire normalizes logId wire bytes to 32-char lowercase hex.
// Accepts 16-byte raw log id or 32 ASCII hex digits.
func logIDHexFromWire(logID []byte) (string, error) {
	if len(logID) == 16 {
		return hex.EncodeToString(logID), nil
	}
	if len(logID) == 32 {
		return NormalizeForestrieHexID32(string(logID))
	}
	return "", fmt.Errorf("logId must be 16 raw bytes or 32 hex characters")
}

func algMatchesDelegationCurve(alg string, curve delegationcert.Curve) bool {
	a := strings.TrimSpace(strings.ToUpper(alg))
	return curve == delegationcert.Secp256r1 && a == "ES256"
}

func delegationIDFromRequest(requestID []byte) ([]byte, error) {
	if len(requestID) >= 16 {
		out := make([]byte, 16)
		copy(out, requestID[:16])
		return out, nil
	}
	out := make([]byte, 16)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("generate delegation id: %w", err)
	}
	return out, nil
}

func leaseTimestampsFromRequest(req *delegationcert.DelegationIssueRequest, now time.Time) (uint64, uint64) {
	issuedAt := uint64(now.Unix())
	var expiresAt uint64
	if req.RequestedTTLSeconds > 0 {
		expiresAt = issuedAt + req.RequestedTTLSeconds
	} else {
		expiresAt = issuedAt + uint64((60 * time.Minute).Seconds())
	}
	return issuedAt, expiresAt
}
