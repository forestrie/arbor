package delegationcert

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Strict CBOR for the verification paths (rules-of-the-road P16).
//
// The default decoder is permissive in ways that matter to a verifier: it
// resolves duplicate map keys last-wins, accepts indefinite-length items,
// and accepts non-canonical integer encodings. Each of those lets one
// artifact have two readings — a certificate whose algorithm is -7 to one
// parser and -65800 to another is a forgery primitive, not a curiosity.
//
// Informational parsing (ParseCertificate's display fields) keeps the
// permissive decoder; only material a signature or a policy decision rests
// on goes through here.
var (
	strictDecMode cbor.DecMode
	canonicalEnc  cbor.EncMode
)

func init() {
	var err error
	strictDecMode, err = cbor.DecOptions{
		// Duplicate keys are rejected rather than silently resolved.
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
		// Definite lengths only: an indefinite-length header has no
		// canonical form to compare against.
		IndefLength: cbor.IndefLengthForbidden,
		// Tags are not part of this profile; see decodeCertificate.
		TagsMd: cbor.TagsForbidden,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("delegationcert: strict DecMode: %v", err))
	}
	// MUST match the producer (build_certificate.go): core-deterministic
	// ordering, RFC 8949 §4.2.1, per rules-of-the-road P16.
	//
	// Not CanonicalEncOptions — that is the older RFC 7049 length-first
	// ordering, which sorts multi-byte map keys differently. With only
	// single-byte header labels the two agree, so the divergence would
	// have stayed invisible until the first multi-byte label and then
	// rejected a perfectly valid certificate.
	canonicalEnc, err = cbor.EncOptions{
		Sort: cbor.SortCoreDeterministic,
	}.EncMode()
	if err != nil {
		panic(fmt.Sprintf("delegationcert: canonical EncMode: %v", err))
	}
}

// strictUnmarshal decodes with the strict mode.
func strictUnmarshal(b []byte, v any) error {
	return strictDecMode.Unmarshal(b, v)
}

// asBstrStrict accepts ONLY a CBOR byte string.
//
// The permissive asBstr also coerces a CBOR array of small integers into
// bytes. That is convenient for informational fields and wrong for a
// verifier: it lets structure be supplied where bytes are required, so a
// hostile encoder can choose which shape a given consumer sees.
func asBstrStrict(v any) ([]byte, bool) {
	b, ok := v.([]byte)
	return b, ok
}

// requireCanonicalMap checks that an encoded CBOR map is in canonical
// form, by decoding it and re-encoding it canonically.
//
// This is what catches non-canonical integer encodings, which no decoder
// option rejects — {1: -7} with the key written as an 8-bit int decodes
// identically to the canonical form, so only a byte comparison sees it.
func requireCanonicalMap(encoded []byte, what string) error {
	var m map[int64]any
	if err := strictUnmarshal(encoded, &m); err != nil {
		return fmt.Errorf("decode %s: %w", what, err)
	}
	reencoded, err := canonicalEnc.Marshal(m)
	if err != nil {
		return fmt.Errorf("re-encode %s: %w", what, err)
	}
	if !bytes.Equal(encoded, reencoded) {
		return fmt.Errorf("%s is not canonical CBOR", what)
	}
	return nil
}
