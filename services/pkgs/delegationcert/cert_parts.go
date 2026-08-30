package delegationcert

import "fmt"

// certParts is a delegation certificate decoded once, strictly.
//
// Every verification path takes these parts rather than re-decoding the
// same bytes. Decoding repeatedly is not merely wasteful: each decode is
// another chance for two readings of one artifact to diverge, which is
// precisely the class of bug strict decoding exists to close.
type certParts struct {
	Protected   []byte
	Unprotected map[int64]any
	Payload     []byte
	Signature   []byte
}

// decodeCertificate decodes and structurally validates a delegation
// certificate: untagged, 4-element, byte strings where byte strings are
// required, canonical protected header, no duplicate or indefinite-length
// CBOR anywhere.
func decodeCertificate(certBytes []byte) (*certParts, error) {
	if len(certBytes) == 0 {
		return nil, fmt.Errorf("empty certificate")
	}
	// Major type 6 is a tag. The profile is an UNTAGGED COSE_Sign1
	// (tag 18 would be 0xd2); silently unwrapping a tag would give one
	// artifact two readings.
	if certBytes[0] >= 0xc0 && certBytes[0] <= 0xdb {
		return nil, fmt.Errorf(
			"delegation certificate must be an untagged COSE_Sign1",
		)
	}

	var arr []any
	if err := strictUnmarshal(certBytes, &arr); err != nil {
		return nil, fmt.Errorf("decode COSE Sign1: %w", err)
	}
	if len(arr) != 4 {
		return nil, fmt.Errorf(
			"unexpected COSE Sign1 array length: %d", len(arr),
		)
	}

	protected, ok := asBstrStrict(arr[0])
	if !ok {
		return nil, fmt.Errorf("COSE protected header is not bstr")
	}
	payload, ok := asBstrStrict(arr[2])
	if !ok {
		return nil, fmt.Errorf("COSE payload is not bstr")
	}
	signature, ok := asBstrStrict(arr[3])
	if !ok {
		return nil, fmt.Errorf("COSE signature is not bstr")
	}

	// The protected header and the payload are both signed, so their exact
	// bytes matter: a non-canonical encoding of either is a second reading
	// of the same artifact.
	if len(protected) > 0 {
		if err := requireCanonicalMap(protected, "protected header"); err != nil {
			return nil, err
		}
	}
	if len(payload) > 0 {
		if err := requireCanonicalMap(payload, "payload"); err != nil {
			return nil, err
		}
	}

	unprotected, err := unprotectedMapFromAny(arr[1])
	if err != nil {
		return nil, fmt.Errorf("COSE unprotected header: %w", err)
	}

	return &certParts{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     payload,
		Signature:   signature,
	}, nil
}

// unprotectedMapFromAny converts the decoded UNPROTECTED header to int64
// keys, skipping entries whose key is not an integer.
//
// Skipping is correct here and only here. COSE permits tstr labels in a
// header map, and the TypeScript verifier (coseUnprotectedToMap) already
// drops non-numeric keys, so a future producer that adds one would
// otherwise hard-fail every arbor verify while canopy kept working — a
// forward-compatibility hazard, not a security one: nothing in the
// unprotected header is signed, and the labels this verifier acts on are
// looked up by integer, so an unrecognised entry cannot displace one.
//
// Everything else stays strict. Duplicate keys, indefinite lengths and
// non-integer keys in the PROTECTED header or the payload are still
// rejected (strictUnmarshal and decodeIntKeyedMapStrict), because those
// bytes are signed.
func unprotectedMapFromAny(v any) (map[int64]any, error) {
	raw, ok := v.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("not a map")
	}
	out := make(map[int64]any, len(raw))
	for k, vv := range raw {
		ki, ok := asInt64(k)
		if !ok {
			continue
		}
		out[ki] = vv
	}
	return out, nil
}

// algFromParts reads the COSE algorithm from decoded parts.
func algFromParts(p *certParts) (int64, error) {
	m, err := decodeIntKeyedMapStrict(p.Protected)
	if err != nil {
		return 0, fmt.Errorf("decode protected header: %w", err)
	}
	alg, ok := asInt64(m[CoseHeaderAlg])
	if !ok {
		return 0, fmt.Errorf("protected header missing alg")
	}
	return alg, nil
}

// decodeIntKeyedMapStrict decodes an int-keyed CBOR map on the strict
// decoder, rejecting a non-integer key. It is the only int-keyed map
// decoder in this package: the signed material (protected header, payload)
// and the informational reader must not disagree about what decodes.
func decodeIntKeyedMapStrict(b []byte) (map[int64]any, error) {
	var raw map[any]any
	if err := strictUnmarshal(b, &raw); err != nil {
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

// hasWebAuthnEnvelope reports whether decoded parts carry an entry at the
// WebAuthn envelope label.
func hasWebAuthnEnvelope(p *certParts) bool {
	_, present := p.Unprotected[CoseHeaderWebAuthnEnvelope]
	return present
}
