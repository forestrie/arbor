package univocity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// The shared KS256 low-s vector. Source of truth: forestrie/protocol
// vectors/fixtures/ks256-low-s.json (cases in vectors/README.md, "KS256
// low-s"); testdata/ holds a byte-identical copy pinned by SHA-256 below
// (see testdata/SOURCE), as does pkgs/delegationcert/testdata/. Do not
// edit the copy; change protocol and re-copy.
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
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != ks256LowSVectorSHA256 {
		t.Fatalf("testdata/ks256-low-s.json sha256 %s is not the pinned protocol vector", got)
	}
	var v ks256LowSVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("vector has no cases")
	}
	return v
}

func decodeKS256LowSCase(t *testing.T, c ks256LowSCase) (coseSign1, []byte) {
	t.Helper()
	cose, _, err := decodeCoseSign1(mustHexBytes(t, c.CoseSign1Hex))
	if err != nil {
		t.Fatal(err)
	}
	return cose, mustHexBytes(t, c.SignerAddressHex)
}

// A recovered KS256 grant signature must be low-s: each reject case is the
// high-s twin of an accept case and recovers the same address, so only the
// s bound refuses it.
func TestVerifyGrantEnvelopeKS256_LowSVector(t *testing.T) {
	v := loadKS256LowSVector(t)
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			cose, owner := decodeKS256LowSCase(t, c)
			err := verifyGrantEnvelope(context.Background(), cose, coseAlgKS256, owner, nil)
			if c.Expect.Result == "accept" && err != nil {
				t.Fatalf("want accept, got %v", err)
			}
			if c.Expect.Result != "accept" {
				// The write handler and the reservation sweep both key on
				// ErrGrantSignatureInvalid; the inner error says why.
				if !errors.Is(err, ErrGrantSignatureInvalid) ||
					!errors.Is(err, errKS256SignatureValues) {
					t.Fatalf("want the low-s refusal, got %v", err)
				}
			}
		})
	}
}

type recordingERC1271 struct{ hash, sig []byte }

func (r *recordingERC1271) HasCode(context.Context, common.Address) (bool, error) {
	return true, nil
}

func (r *recordingERC1271) IsValidSignature(_ context.Context, _ common.Address, hash, sig []byte) error {
	r.hash, r.sig = hash, sig
	return nil
}

// A contract owner judges its own signature: the high-s signature reaches
// ERC-1271 unchanged.
func TestVerifyGrantEnvelopeKS256_ERC1271GetsHighSUnchanged(t *testing.T) {
	v := loadKS256LowSVector(t)
	for _, c := range v.Cases {
		if c.Name != "reject/high-s" {
			continue
		}
		cose, owner := decodeKS256LowSCase(t, c)
		rec := &recordingERC1271{}
		if err := verifyGrantEnvelope(context.Background(), cose, coseAlgKS256, owner, rec); err != nil {
			t.Fatalf("contract owner: %v", err)
		}
		if got := hex.EncodeToString(rec.hash); got != v.DigestHex {
			t.Fatalf("ERC-1271 hash %s, want %s", got, v.DigestHex)
		}
		if got := hex.EncodeToString(rec.sig); got != c.SignatureHex {
			t.Fatalf("ERC-1271 signature %s, want %s", got, c.SignatureHex)
		}
		return
	}
	t.Fatal("vector has no reject/high-s case")
}
