package custodian

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestDigestFromSignRequest_PayloadHash(t *testing.T) {
	d := make([]byte, 32)
	for i := range d {
		d[i] = byte(i)
	}
	got, err := DigestFromSignRequest(&SignRequest{PayloadHash: d})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(d) {
		t.Fatalf("digest mismatch")
	}
}

func TestDigestFromSignRequest_Payload(t *testing.T) {
	got, err := DigestFromSignRequest(&SignRequest{Payload: []byte("foo")})
	if err != nil {
		t.Fatal(err)
	}
	wantHex := "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
	want, _ := hex.DecodeString(wantHex)
	if string(got) != string(want) {
		t.Fatalf("digest mismatch, got %x want %s", got, wantHex)
	}
}

func TestDigestFromSignRequest_BothFields(t *testing.T) {
	_, err := DigestFromSignRequest(&SignRequest{PayloadHash: []byte{1}, Payload: []byte{2}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDigestFromSignRequest_WrongHashLen(t *testing.T) {
	_, err := DigestFromSignRequest(&SignRequest{PayloadHash: []byte{1, 2, 3}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDigestFromSignRequest_Empty(t *testing.T) {
	_, err := DigestFromSignRequest(&SignRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestKidFromECDSAPublicKey_Deterministic(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	a, err := KidFromECDSAPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 16 {
		t.Fatalf("kid len %d", len(a))
	}
	b, err := KidFromECDSAPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("kid not deterministic")
	}
}
