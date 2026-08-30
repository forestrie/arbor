package univocity

import "testing"

// A passkey root is an ordinary 64-byte P-256 point, so it must resolve as
// ES256 — never as ALG_ES256_WEBAUTHN (-65800).
//
// This guards the premise the FOR-551 sealer fix rests on.
// ALG_ES256_WEBAUTHN is a SIGNATURE algorithm, not a key type: only the
// delegation certificate's signature envelope is WebAuthn, and the key it
// verifies against is a plain P-256 point. If a trust root were ever
// advertised as -65800, the sealer's ES256 branch would stop being
// reached and passkey-rooted logs would fail upstream with "unsupported
// trust root alg" instead of verifying.
//
// FOR-551 was originally filed claiming that upstream failure was a real
// mode. It is not, and this test is what keeps that true.
const coseAlgES256WebAuthn = -65800

func TestGrantDataIdentityInfersES256FromLength(t *testing.T) {
	alg, key, ok := grantDataIdentity(make([]byte, 64))
	if !ok {
		t.Fatal("a 64-byte grantData must resolve")
	}
	if alg != coseAlgES256 {
		t.Fatalf("64-byte grantData: got alg %d, want %d (ES256)",
			alg, coseAlgES256)
	}
	if alg == coseAlgES256WebAuthn {
		t.Fatal("a trust root must never be advertised as -65800")
	}
	if len(key) != 64 {
		t.Fatalf("key length: got %d, want 64", len(key))
	}
}

func TestGrantDataIdentityInfersKS256FromLength(t *testing.T) {
	alg, key, ok := grantDataIdentity(make([]byte, 20))
	if !ok {
		t.Fatal("a 20-byte grantData must resolve")
	}
	if alg != coseAlgKS256 {
		t.Fatalf("20-byte grantData: got alg %d, want %d (KS256)",
			alg, coseAlgKS256)
	}
	if len(key) != 20 {
		t.Fatalf("key length: got %d, want 20", len(key))
	}
}

func TestGrantDataIdentityRejectsOtherLengths(t *testing.T) {
	for _, n := range []int{0, 1, 19, 21, 32, 33, 63, 65, 128} {
		if _, _, ok := grantDataIdentity(make([]byte, n)); ok {
			t.Fatalf("%d-byte grantData must not resolve", n)
		}
	}
}

// The bootstrap path infers the same way and must agree.
func TestBootstrapIdentityAgreesWithGrantData(t *testing.T) {
	for _, n := range []int{64, 20} {
		wantAlg, _, ok := grantDataIdentity(make([]byte, n))
		if !ok {
			t.Fatalf("%d-byte grantData must resolve", n)
		}
		gotAlg, ok := bootstrapIdentityFromKey(make([]byte, n))
		if !ok {
			t.Fatalf("%d-byte bootstrap key must resolve", n)
		}
		if gotAlg != wantAlg {
			t.Fatalf("%d bytes: bootstrap alg %d != grantData alg %d",
				n, gotAlg, wantAlg)
		}
	}
}
