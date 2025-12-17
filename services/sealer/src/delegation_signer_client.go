package sealer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/fxamacker/cbor/v2"
)

type DelegationCurve string

const (
	DelegationCurveSecp256k1 DelegationCurve = "secp256k1"
	DelegationCurveSecp256r1 DelegationCurve = "secp256r1"
)

func ParseDelegationCurve(raw string) (DelegationCurve, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	switch trimmed {
	case "", "secp256k1", "k1", "es256k":
		return DelegationCurveSecp256k1, nil
	case "secp256r1", "p-256", "p256", "r1", "es256":
		return DelegationCurveSecp256r1, nil
	default:
		return "", fmt.Errorf("expected secp256k1 or secp256r1, got %q", raw)
	}
}

type DelegatedKeypair struct {
	Curve DelegationCurve
	X     [32]byte
	Y     [32]byte
}

func GenerateDelegatedKeypair(curve DelegationCurve) (*DelegatedKeypair, error) {
	switch curve {
	case DelegationCurveSecp256r1:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate P-256 key: %w", err)
		}
		var x, y [32]byte
		priv.PublicKey.X.FillBytes(x[:])
		priv.PublicKey.Y.FillBytes(y[:])
		return &DelegatedKeypair{Curve: curve, X: x, Y: y}, nil
	case DelegationCurveSecp256k1:
		priv, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("generate secp256k1 key: %w", err)
		}
		pub := priv.PubKey()
		// Uncompressed SEC1: 0x04 || X(32) || Y(32)
		uc := pub.SerializeUncompressed()
		if len(uc) != 65 || uc[0] != 0x04 {
			return nil, fmt.Errorf("unexpected secp256k1 uncompressed pubkey encoding")
		}
		var x, y [32]byte
		copy(x[:], uc[1:33])
		copy(y[:], uc[33:65])
		return &DelegatedKeypair{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported curve %q", curve)
	}
}

type DelegationCertificateInfo struct {
	CertSHA256             string
	CertSize               int
	ProtectedAlg           int64
	ProtectedCty           string
	ProtectedKidHex        string
	PayloadDelegationIDHex string
	PayloadLogID           string
	PayloadLogIDPrefix     string
	PayloadMmrStart        string
	PayloadMmrEnd          string
	PayloadDelegatedCurve  string
	SignatureSize          int
}

func RequestDelegationCertificate(
	ctx context.Context,
	httpClient *HTTPClient,
	signerBaseURL string,
	accessToken string,
	curveRaw string,
	logIDPrefix string,
) (*DelegationCertificateInfo, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("http client is nil")
	}
	if strings.TrimSpace(signerBaseURL) == "" {
		return nil, fmt.Errorf("signer base URL is empty")
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("access token is empty")
	}

	curve, err := ParseDelegationCurve(curveRaw)
	if err != nil {
		return nil, err
	}

	keypair, err := GenerateDelegatedKeypair(curve)
	if err != nil {
		return nil, err
	}

	// Delegation request schema is string-keyed CBOR map.
	// delegated_pubkey is a COSE_Key EC2 map with integer labels.
	crv := int64(8) // secp256k1
	if curve == DelegationCurveSecp256r1 {
		crv = 1
	}

	coseKey := map[int64]any{
		1:  int64(2),     // kty = EC2
		-1: crv,          // crv
		-2: keypair.X[:], // x (bstr, 32 bytes)
		-3: keypair.Y[:], // y (bstr, 32 bytes)
	}

	reqMap := map[string]any{
		"delegated_pubkey": coseKey,
		// Always include constraints as a map (worker expects a map).
		"constraints": map[string]any{},
	}
	if strings.TrimSpace(logIDPrefix) != "" {
		reqMap["log_id_prefix"] = strings.TrimSpace(logIDPrefix)
	}

	body, err := cbor.Marshal(reqMap)
	if err != nil {
		return nil, fmt.Errorf("encode CBOR request: %w", err)
	}

	endpoint := strings.TrimRight(strings.TrimSpace(signerBaseURL), "/") + "/api/delegations"
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/cbor")

	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("call delegation signer: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Attempt to produce a safe, useful error message.
		preview := respBytes
		if len(preview) > 1024 {
			preview = preview[:1024]
		}
		return nil, fmt.Errorf(
			"delegation signer returned status=%d content_type=%q body_len=%d body_preview_hex=%s",
			resp.StatusCode,
			resp.Header.Get("Content-Type"),
			len(respBytes),
			hex.EncodeToString(preview),
		)
	}

	info, err := ParseDelegationCertificate(respBytes)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func ParseDelegationCertificate(certBytes []byte) (*DelegationCertificateInfo, error) {
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

	protectedBytes, ok := coseArr[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("COSE_Sign1[0] (protected) is not bstr")
	}
	payloadBytes, ok := coseArr[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("COSE_Sign1[2] (payload) is not bstr")
	}
	signature, ok := coseArr[3].([]byte)
	if !ok {
		return nil, fmt.Errorf("COSE_Sign1[3] (signature) is not bstr")
	}

	protectedMap, err := decodeIntKeyedMap(protectedBytes)
	if err != nil {
		return nil, fmt.Errorf("decode protected header: %w", err)
	}
	payloadMap, err := decodeIntKeyedMap(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	alg, _ := asInt64(protectedMap[1])
	cty, _ := protectedMap[3].(string)
	kidHex := ""
	if kid, ok := protectedMap[4].([]byte); ok && len(kid) > 0 {
		kidHex = hex.EncodeToString(kid)
	}

	logID, _ := payloadMap[1].(string)
	mmrStart := toNumericString(payloadMap[3])
	mmrEnd := toNumericString(payloadMap[4])

	delegationIDHex := ""
	if did, ok := payloadMap[10].([]byte); ok && len(did) > 0 {
		delegationIDHex = hex.EncodeToString(did)
	}

	// Extract delegated key curve from payload[5].
	delegatedCurve := ""
	if rawKey, ok := payloadMap[5]; ok {
		if m, ok := normalizeAnyIntKeyedMap(rawKey); ok {
			if crv, ok := asInt64(m[-1]); ok {
				switch crv {
				case 8:
					delegatedCurve = string(DelegationCurveSecp256k1)
				case 1:
					delegatedCurve = string(DelegationCurveSecp256r1)
				default:
					delegatedCurve = fmt.Sprintf("unknown(%d)", crv)
				}
			}
		}
	}

	// Extract optional constraints.log_id_prefix from payload[6].
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

	return &DelegationCertificateInfo{
		CertSHA256:             certSHA,
		CertSize:               len(certBytes),
		ProtectedAlg:           alg,
		ProtectedCty:           cty,
		ProtectedKidHex:        kidHex,
		PayloadDelegationIDHex: delegationIDHex,
		PayloadLogID:           logID,
		PayloadLogIDPrefix:     logIDPrefix,
		PayloadMmrStart:        mmrStart,
		PayloadMmrEnd:          mmrEnd,
		PayloadDelegatedCurve:  delegatedCurve,
		SignatureSize:          len(signature),
	}, nil
}

func decodeIntKeyedMap(b []byte) (map[int64]any, error) {
	var raw map[any]any
	if err := cbor.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make(map[int64]any, len(raw))
	for k, v := range raw {
		ki, ok := asInt64(k)
		if !ok {
			return nil, fmt.Errorf("non-integer CBOR map key: %T", k)
		}
		out[ki] = v
	}
	return out, nil
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
