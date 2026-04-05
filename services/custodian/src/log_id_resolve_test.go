package custodian

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeLogIDForKMSLabel(t *testing.T) {
	got, err := NormalizeLogIDForKMSLabel(" 0xAbCdEf01 ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "abcdef01" {
		t.Fatalf("got %q", got)
	}
	if _, err := NormalizeLogIDForKMSLabel("no!"); err == nil {
		t.Fatal("expected error")
	}
}

func TestLogIDKeyLRU(t *testing.T) {
	c := newLogIDKeyLRU(2)
	if _, hit := c.Get("a"); hit {
		t.Fatal("unexpected hit")
	}
	c.Put("a", "k1")
	c.Put("b", "k2")
	if kid, hit := c.Get("a"); !hit || kid != "k1" {
		t.Fatalf("a: hit=%v kid=%q", hit, kid)
	}
	c.Put("c", "k3")
	if _, hit := c.Get("b"); hit {
		t.Fatal("b should be evicted (capacity 2)")
	}
	if kid, hit := c.Get("c"); !hit || kid != "k3" {
		t.Fatalf("c: hit=%v kid=%q", hit, kid)
	}
}

func TestQueryLogIDTreatAsLogID(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://localhost/x?log-id=true", nil)
	if !queryLogIDTreatAsLogID(r) {
		t.Fatal("expected true for log-id=true")
	}
	r2 := httptest.NewRequest(http.MethodGet, "http://localhost/x?log-id=1", nil)
	if !queryLogIDTreatAsLogID(r2) {
		t.Fatal("expected true for log-id=1")
	}
	r3 := httptest.NewRequest(http.MethodGet, "http://localhost/x", nil)
	if queryLogIDTreatAsLogID(r3) {
		t.Fatal("expected false")
	}
}

func TestResolveCustodianKeyFromEntries_NoKeysNotRootReturnsSentinel(t *testing.T) {
	_, err := resolveCustodianKeyFromEntries("abcd00000000000000000000000000", nil, "fedcba000000000000000000000000", nil)
	if !errors.Is(err, ErrNoCustodianKeyForLogID) {
		t.Fatalf("expected ErrNoCustodianKeyForLogID, got %v", err)
	}
}

func TestResolveCustodianKeyFromEntries_NoKeysRootMatchReturnsBootstrap(t *testing.T) {
	kid, err := resolveCustodianKeyFromEntries(
		"123e4567e89b12d3a456426614174000",
		nil,
		"123e4567-e89b-12d3-a456-426614174000",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if kid != BootstrapKeyAlias {
		t.Fatalf("got %q", kid)
	}
}

func TestResolveCustodianKeyFromEntries_SingleKey(t *testing.T) {
	kid, err := resolveCustodianKeyFromEntries(
		"abcd00000000000000000000000000",
		[]KeyListEntry{{KeyID: "short-kid", Version: 1}},
		"",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if kid != "short-kid" {
		t.Fatalf("got %q", kid)
	}
}

func TestResolveCustodianKeyFromEntries_Ambiguous(t *testing.T) {
	_, err := resolveCustodianKeyFromEntries(
		"abcd00000000000000000000000000",
		[]KeyListEntry{{KeyID: "a", Version: 1}, {KeyID: "b", Version: 1}},
		"",
		nil,
	)
	if !errors.Is(err, ErrAmbiguousCustodianLogID) {
		t.Fatalf("expected ErrAmbiguousCustodianLogID, got %v", err)
	}
}
