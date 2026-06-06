package sealer

import (
	"fmt"
	"strings"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/fxamacker/cbor/v2"
)

const (
	coseAlgES256  int64 = -7
	coseAlgKS256  int64 = -65799
)

// trustRootV2Response is the opaque (alg, key) CBOR shape from univocity v2.
type trustRootV2Response struct {
	LogID           []byte `cbor:"logId"`
	Alg             int64  `cbor:"alg"`
	Key             []byte `cbor:"key"`
	ChainID         string `cbor:"chainId,omitempty"`
	ContractAddress string `cbor:"contractAddress,omitempty"`
}

// LogSigningKeyFromTrustRootCBOR decodes v2 (alg:int, key:bstr) or v1 (alg:"ES256", x, y).
func LogSigningKeyFromTrustRootCBOR(body []byte) (LogSigningKey, error) {
	if len(body) == 0 {
		return LogSigningKey{}, fmt.Errorf("trust root body empty")
	}

	// Try v2 opaque shape first.
	var v2 trustRootV2Response
	if err := cbor.Unmarshal(body, &v2); err == nil && v2.Alg != 0 && len(v2.Key) > 0 {
		return logSigningKeyFromAlgKey(v2.Alg, v2.Key)
	}

	var v1 TrustRootResponse
	if err := cbor.Unmarshal(body, &v1); err != nil {
		return LogSigningKey{}, fmt.Errorf("decode trust root CBOR: %w", err)
	}
	if strings.EqualFold(strings.TrimSpace(v1.Alg), "KS256") && len(v1.Key) == 20 {
		return LogSigningKey{
			Alg:         "KS256",
			AlgInt:      coseAlgKS256,
			KS256Signer: append([]byte(nil), v1.Key...),
		}, nil
	}
	pemStr, err := EncodeECDSAPublicKeyPEMFromXY(v1.Alg, v1.X, v1.Y)
	if err != nil {
		return LogSigningKey{}, err
	}
	return LogSigningKey{
		PublicKeyPEM: pemStr,
		Alg:          strings.TrimSpace(v1.Alg),
		AlgInt:       coseAlgES256,
	}, nil
}

func logSigningKeyFromAlgKey(alg int64, key []byte) (LogSigningKey, error) {
	switch alg {
	case coseAlgKS256:
		if len(key) != 20 {
			return LogSigningKey{}, fmt.Errorf("KS256 trust root key must be 20 bytes, got %d", len(key))
		}
		return LogSigningKey{
			Alg:         "KS256",
			AlgInt:      coseAlgKS256,
			KS256Signer: append([]byte(nil), key...),
		}, nil
	case coseAlgES256:
		if len(key) != 64 {
			return LogSigningKey{}, fmt.Errorf("ES256 trust root key must be 64 bytes, got %d", len(key))
		}
		x, y := key[:32], key[32:]
		pemStr, err := EncodeECDSAPublicKeyPEMFromXY("ES256", x, y)
		if err != nil {
			return LogSigningKey{}, err
		}
		return LogSigningKey{
			PublicKeyPEM: pemStr,
			Alg:          "ES256",
			AlgInt:       coseAlgES256,
		}, nil
	default:
		return LogSigningKey{}, fmt.Errorf("unsupported trust root alg %d", alg)
	}
}

// IsKS256Root reports whether the trust root is a KS256 Ethereum address signer.
func (k LogSigningKey) IsKS256Root() bool {
	return k.AlgInt == coseAlgKS256 || strings.EqualFold(k.Alg, "KS256")
}

// DelegatedCurveForRoot returns the expected delegated ephemeral curve.
func (k LogSigningKey) DelegatedCurve() delegationcert.Curve {
	return delegationcert.Secp256r1
}
