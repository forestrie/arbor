package delegationcert

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ParseCertificate decodes an untagged COSE_Sign1 delegation certificate.
func ParseCertificate(certBytes []byte) (*CertificateInfo, error) {
	if len(certBytes) == 0 {
		return nil, fmt.Errorf("empty certificate bytes")
	}

	sum := sha256.Sum256(certBytes)
	certSHA := hex.EncodeToString(sum[:])

	var coseArr []any
	if err := cbor.Unmarshal(certBytes, &coseArr); err != nil {
		return nil, fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	if len(coseArr) != 4 {
		return nil, fmt.Errorf("unexpected COSE_Sign1 array length: %d", len(coseArr))
	}

	// The structural elements go through the strict accessor even here.
	// The display fields are informational, but a reader that accepts a
	// shape the verifier refuses gives one certificate two readings, and
	// this is the function the sealer logs from.
	protectedBytes, ok := asBstrStrict(coseArr[0])
	if !ok {
		return nil, fmt.Errorf("COSE_Sign1[0] (protected) is not bstr (type=%T)", coseArr[0])
	}
	payloadBytes, ok := asBstrStrict(coseArr[2])
	if !ok {
		return nil, fmt.Errorf("COSE_Sign1[2] (payload) is not bstr (type=%T)", coseArr[2])
	}
	signature, ok := asBstrStrict(coseArr[3])
	if !ok {
		return nil, fmt.Errorf("COSE_Sign1[3] (signature) is not bstr (type=%T)", coseArr[3])
	}

	protectedMap, err := decodeIntKeyedMapStrict(protectedBytes)
	if err != nil {
		return nil, fmt.Errorf("decode protected header: %w", err)
	}
	payloadMap, err := decodeIntKeyedMapStrict(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	alg, _ := asInt64(protectedMap[1])
	cty, _ := protectedMap[3].(string)
	kidHex := ""
	if kid, ok := asBstr(protectedMap[4]); ok && len(kid) > 0 {
		kidHex = hex.EncodeToString(kid)
	}

	logID, _ := payloadMap[1].(string)
	mmrStart, err := payloadRangeBound(payloadMap, PayloadLabelMmrStart)
	if err != nil {
		return nil, err
	}
	mmrEnd, err := payloadRangeBound(payloadMap, PayloadLabelMmrEnd)
	if err != nil {
		return nil, err
	}
	if err := ValidateMMRRange(mmrStart, mmrEnd); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	issuedAt := toNumericString(payloadMap[8])
	expiresAt := toNumericString(payloadMap[9])

	issuedAtUnix, _ := asUint64(payloadMap[8])
	expiresAtUnix, _ := asUint64(payloadMap[9])

	delegationIDHex := ""
	if did, ok := asBstr(payloadMap[10]); ok && len(did) > 0 {
		delegationIDHex = hex.EncodeToString(did)
	}

	delegatedCurve := ""
	if rawKey, ok := payloadMap[5]; ok {
		if m, ok := normalizeAnyIntKeyedMap(rawKey); ok {
			if crv, ok := asInt64(m[-1]); ok {
				switch crv {
				case 1:
					delegatedCurve = string(Secp256r1)
				default:
					delegatedCurve = fmt.Sprintf("unknown(%d)", crv)
				}
			}
		}
	}

	logIDPrefix := ""
	if cRaw, ok := payloadMap[6]; ok {
		switch c := cRaw.(type) {
		case map[any]any:
			if v, ok := c["log_id_prefix"]; ok {
				if s, ok := v.(string); ok {
					logIDPrefix = s
				}
			}
		case map[string]any:
			if v, ok := c["log_id_prefix"]; ok {
				if s, ok := v.(string); ok {
					logIDPrefix = s
				}
			}
		}
	}

	return &CertificateInfo{
		CertSHA256:             certSHA,
		CertSize:               len(certBytes),
		ProtectedAlg:           alg,
		ProtectedCty:           cty,
		ProtectedKidHex:        kidHex,
		PayloadDelegationIDHex: delegationIDHex,
		PayloadLogID:           logID,
		PayloadLogIDPrefix:     logIDPrefix,
		MMRStart:               mmrStart,
		MMREnd:                 mmrEnd,
		PayloadIssuedAt:        issuedAt,
		PayloadExpiresAt:       expiresAt,
		PayloadIssuedAtUnix:    issuedAtUnix,
		PayloadExpiresAtUnix:   expiresAtUnix,
		PayloadDelegatedCurve:  delegatedCurve,
		SignatureSize:          len(signature),
	}, nil
}

// payloadRangeBound reads an MMR range bound (payload label 3 or 4). The
// bound must be present and must be a CBOR unsigned integer (major type
// 0), which the decoder's default IntDec yields as uint64. Anything else —
// a missing label, a float, a negative int, a string, null — is
// ErrMMRRangeBound: an absent bound must not read as 0, and a float is not
// an index, even a whole-number one. A tag-2 bignum never gets here: the
// strict decoder forbids tags.
func payloadRangeBound(payload map[int64]any, label int64) (uint64, error) {
	v, present := payload[label]
	if !present {
		return 0, fmt.Errorf("%w: payload label %d is missing", ErrMMRRangeBound, label)
	}
	u, ok := v.(uint64)
	if !ok {
		return 0, fmt.Errorf("%w: payload label %d has type %T", ErrMMRRangeBound, label, v)
	}
	return u, nil
}

func asBstr(v any) ([]byte, bool) {
	switch t := v.(type) {
	case nil:
		return nil, false
	case []byte:
		return t, true
	case cbor.RawMessage:
		return []byte(t), true
	case cbor.Tag:
		return asBstr(t.Content)
	case cbor.RawTag:
		var inner any
		if err := cbor.Unmarshal([]byte(t.Content), &inner); err != nil {
			return nil, false
		}
		return asBstr(inner)
	case []any:
		out := make([]byte, len(t))
		for i, el := range t {
			n, ok := asInt64(el)
			if !ok || n < 0 || n > 255 {
				return nil, false
			}
			out[i] = byte(n)
		}
		return out, true
	default:
		return nil, false
	}
}

func normalizeAnyIntKeyedMap(v any) (map[int64]any, bool) {
	raw, ok := v.(map[any]any)
	if !ok {
		return nil, false
	}
	out := make(map[int64]any, len(raw))
	for k, vv := range raw {
		ki, ok := asInt64(k)
		if !ok {
			continue
		}
		out[ki] = vv
	}
	return out, true
}

func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int8:
		return int64(t), true
	case int16:
		return int64(t), true
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case uint:
		return int64(t), true
	case uint8:
		return int64(t), true
	case uint16:
		return int64(t), true
	case uint32:
		return int64(t), true
	case uint64:
		if t > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(t), true
	default:
		return 0, false
	}
}

func asUint64(v any) (uint64, bool) {
	switch t := v.(type) {
	case uint64:
		return t, true
	case uint32:
		return uint64(t), true
	case uint16:
		return uint64(t), true
	case uint8:
		return uint64(t), true
	case int64:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	case int32:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	case int16:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	case int8:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	case int:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	case uint:
		return uint64(t), true
	default:
		return 0, false
	}
}

func toNumericString(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case uint64:
		return fmt.Sprintf("%d", t)
	case uint32:
		return fmt.Sprintf("%d", t)
	case uint16:
		return fmt.Sprintf("%d", t)
	case uint8:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case int32:
		return fmt.Sprintf("%d", t)
	case int16:
		return fmt.Sprintf("%d", t)
	case int8:
		return fmt.Sprintf("%d", t)
	case int:
		return fmt.Sprintf("%d", t)
	default:
		return fmt.Sprintf("%v", t)
	}
}
