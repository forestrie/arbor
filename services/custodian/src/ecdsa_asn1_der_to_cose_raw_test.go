package custodian

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestEcdsaDERSignatureToIEEE1363_roundTripP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("custodian cose sig_structure digest"))
	der, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ecdsaDERSignatureToIEEE1363(der, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 64 {
		t.Fatalf("len(raw)=%d want 64", len(raw))
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	if !ecdsa.Verify(&priv.PublicKey, hash[:], r, s) {
		t.Fatal("ecdsa.Verify failed after DER→IEEE1363")
	}
}

func TestEcdsaDERSignatureToIEEE1363_invalidDER(t *testing.T) {
	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"empty", nil},
		{"garbage", []byte{0x01, 0x02, 0x03}},
		{"truncated_sequence", []byte{0x30, 0x03, 0x02, 0x01}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ecdsaDERSignatureToIEEE1363(tc.der, 32)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
