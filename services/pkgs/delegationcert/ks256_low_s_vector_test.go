package delegationcert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// The shared KS256 low-s vector. Source of truth: forestrie/protocol
// vectors/fixtures/ks256-low-s.json (cases in vectors/README.md, "KS256
// low-s"); testdata/ holds a byte-identical copy pinned by SHA-256 below,
// as does univocity/src/testdata/. Do not edit the copy; change protocol
// and re-copy.
const ks256LowSVectorSHA256 = "3a325aaa1bb296316f3f4ef8e2d8a8ae4c1728c00fc283f3cdd2438a2c9d88dc"

type ks256LowSCase struct {
	Name             string `json:"name"`
	SignerAddressHex string `json:"signer_address_hex"`
	SignatureHex     string `json:"signature_hex"`
	CoseSign1Hex     string `json:"cose_sign1_hex"`
	Expect           struct {
		Result string `json:"result"`
	} `json:"expect"`
}

type ks256LowSVector struct {
	DigestHex string          `json:"digest_hex"`
	Cases     []ks256LowSCase `json:"cases"`
}

func loadKS256LowSVector(t *testing.T) ks256LowSVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/ks256-low-s.json")
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	require.Equal(t, ks256LowSVectorSHA256, hex.EncodeToString(sum[:]),
		"testdata/ks256-low-s.json is not the pinned protocol vector")
	var v ks256LowSVector
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Cases)
	return v
}

// A recovered KS256 signature must be low-s: each reject case is the high-s
// twin of an accept case and recovers the same address, so only the s
// bound refuses it.
func TestVerifyCertificateSignatureKS256_LowSVector(t *testing.T) {
	v := loadKS256LowSVector(t)
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			err := VerifyCertificateSignatureKS256(
				mustHex(t, c.CoseSign1Hex), mustHex(t, c.SignerAddressHex), nil)
			if c.Expect.Result == "accept" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

type recordingERC1271 struct{ hash, sig []byte }

func (r *recordingERC1271) HasCode(context.Context, []byte) (bool, error) { return true, nil }

func (r *recordingERC1271) IsValidSignature(_ context.Context, _, hash, sig []byte) error {
	r.hash, r.sig = hash, sig
	return nil
}

// A contract root judges its own signature: the high-s signature reaches
// ERC-1271 unchanged.
func TestVerifyCertificateSignatureKS256_ERC1271GetsHighSUnchanged(t *testing.T) {
	v := loadKS256LowSVector(t)
	var highS ks256LowSCase
	for _, c := range v.Cases {
		if c.Name == "reject/high-s" {
			highS = c
		}
	}
	require.NotEmpty(t, highS.Name)
	rec := &recordingERC1271{}
	require.NoError(t, VerifyCertificateSignatureKS256(
		mustHex(t, highS.CoseSign1Hex), mustHex(t, highS.SignerAddressHex), rec))
	require.Equal(t, v.DigestHex, hex.EncodeToString(rec.hash))
	require.Equal(t, highS.SignatureHex, hex.EncodeToString(rec.sig))
}
