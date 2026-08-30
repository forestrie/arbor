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

	// The protected header is signed, so its exact bytes matter.
	if len(protected) > 0 {
		if err := requireCanonicalMap(protected, "protected header"); err != nil {
			return nil, err
		}
	}

	unprotected, err := strictIntKeyedMapFromAny(arr[1])
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

// strictIntKeyedMapFromAny converts a decoded CBOR map to int64 keys,
// rejecting non-integer keys rather than skipping them. The permissive
// normalizeAnyIntKeyedMap drops keys it cannot interpret, which would let
// an unrecognised entry pass unnoticed.
func strictIntKeyedMapFromAny(v any) (map[int64]any, error) {
	raw, ok := v.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("not a map")
	}
	out := make(map[int64]any, len(raw))
	for k, vv := range raw {
		ki, ok := asInt64(k)
		if !ok {
			return nil, fmt.Errorf("non-integer map key: %T", k)
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

// decodeIntKeyedMapStrict is decodeIntKeyedMap on the strict decoder.
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
