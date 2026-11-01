package delegationcert

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// The MMR range labels (3, 4) are uint64 end to end: ParseCertificate reads
// them with a strict type assertion so a value above 2^53 survives exactly.
// A missing or non-integer label is a parse error, because an absent bound
// must not read as 0 and a float is not an index, even a whole-number one.

const rangeTestLogID = "0123456789abcdef0123456789abcdef"

// rangeTestCert builds an unsigned-but-well-formed certificate over
// [start, end] with the package's own builder. ParseCertificate does not
// verify the signature, so a zero signature is enough.
func rangeTestCert(t *testing.T, start, end uint64) []byte {
	t.Helper()
	dk, err := NewDelegatedCoseKey(Secp256r1, make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)
	tbs, err := BuildDelegationToBeSigned(Secp256r1, make([]byte, 16), DelegationInput{
		LogID:        rangeTestLogID,
		MmrStart:     start,
		MmrEnd:       end,
		DelegatedKey: dk,
		DelegationID: make([]byte, 16),
		IssuedAt:     1000,
		ExpiresAt:    2000,
	})
	require.NoError(t, err)
	cert, err := AssembleDelegationCert(tbs, make([]byte, 64))
	require.NoError(t, err)
	return cert
}

// rangeTestCertWithPayload assembles a certificate around a hand-built
// payload map, for shapes the builder refuses to produce.
func rangeTestCertWithPayload(t *testing.T, payload map[int64]any) []byte {
	t.Helper()
	protected, err := encodeDeterministicIntKeyedMap(map[int64]any{
		CoseHeaderAlg: CoseAlgES256,
		CoseHeaderCty: DelegationContentType,
		CoseHeaderKid: make([]byte, 16),
	})
	require.NoError(t, err)
	payloadBytes, err := encodeDeterministicIntKeyedMap(payload)
	require.NoError(t, err)
	cert, err := AssembleDelegationCert(&DelegationToBeSigned{
		ProtectedBytes: protected,
		PayloadBytes:   payloadBytes,
	}, make([]byte, 64))
	require.NoError(t, err)
	return cert
}

func rangeTestPayload(t *testing.T) map[int64]any {
	t.Helper()
	dk, err := NewDelegatedCoseKey(Secp256r1, make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)
	return map[int64]any{
		PayloadLabelLogID:        rangeTestLogID,
		PayloadLabelMmrStart:     uint64(0),
		PayloadLabelMmrEnd:       uint64(63),
		PayloadLabelDelegatedKey: dk.ToCBORMap(),
		PayloadLabelConstraints:  map[string]any{},
		PayloadLabelSchemaVer:    int64(1),
		PayloadLabelDelegationID: make([]byte, 16),
	}
}

func TestParseCertificate_RangeUint64(t *testing.T) {
	cases := []struct {
		name       string
		start, end uint64
	}{
		{"2^32+1", 1<<32 + 1, 1<<32 + 1},
		{"2^53+1", 1<<53 + 1, 1<<53 + 1},
		{"2^64-1", math.MaxUint64, math.MaxUint64},
		{"zero to 2^64-1", 0, math.MaxUint64},
		{"2^32+1 to 2^53+1", 1<<32 + 1, 1<<53 + 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			info, err := ParseCertificate(rangeTestCert(t, c.start, c.end))
			require.NoError(t, err)
			require.Equal(t, c.start, info.MMRStart)
			require.Equal(t, c.end, info.MMREnd)
		})
	}
}

// TestParseCertificate_WebAuthnGolden2Pow40 runs the real-authenticator
// golden (mmrEnd = 2^40, captured from a platform authenticator; the source
// of truth is canopy delegation-cose testdata) through ParseCertificate.
func TestParseCertificate_WebAuthnGolden2Pow40(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "publishproof", "testdata", "webauthn-real-authenticator-golden.json"))
	require.NoError(t, err)
	var g struct {
		LogIDHex    string `json:"logIdHex"`
		MMRStart    string `json:"mmrStart"`
		MMREnd      string `json:"mmrEnd"`
		Certificate struct {
			CoseSign1 string `json:"coseSign1"`
		} `json:"certificate"`
	}
	require.NoError(t, json.Unmarshal(raw, &g))
	cert, err := hex.DecodeString(g.Certificate.CoseSign1)
	require.NoError(t, err)

	info, err := ParseCertificate(cert)
	require.NoError(t, err)

	wantStart, err := strconv.ParseUint(g.MMRStart, 10, 64)
	require.NoError(t, err)
	wantEnd, err := strconv.ParseUint(g.MMREnd, 10, 64)
	require.NoError(t, err)
	require.Equal(t, uint64(1)<<40, wantEnd, "golden is the 2^40 vector")
	require.Equal(t, g.LogIDHex, info.PayloadLogID)
	require.Equal(t, wantStart, info.MMRStart)
	require.Equal(t, wantEnd, info.MMREnd)
}

func TestParseCertificate_RangeRejects(t *testing.T) {
	// bignum2 is a CBOR tag-2 (positive bignum) whose value, 63, would fit
	// a uint64: the profile forbids tags, so it is refused at decode
	// rather than read as a bound.
	bignum2 := cbor.Tag{Number: 2, Content: []byte{63}}
	cases := []struct {
		name   string
		mutate func(p map[int64]any)
		// Exactly one of wantIs and wantText is set.
		wantIs   error
		wantText string
	}{
		{"missing label 3", func(p map[int64]any) { delete(p, PayloadLabelMmrStart) }, ErrMMRRangeBound, ""},
		{"missing label 4", func(p map[int64]any) { delete(p, PayloadLabelMmrEnd) }, ErrMMRRangeBound, ""},
		{"float label 4", func(p map[int64]any) { p[PayloadLabelMmrEnd] = float64(63) }, ErrMMRRangeBound, ""},
		{"float label 3", func(p map[int64]any) { p[PayloadLabelMmrStart] = float64(0) }, ErrMMRRangeBound, ""},
		{"negative label 3", func(p map[int64]any) { p[PayloadLabelMmrStart] = int64(-1) }, ErrMMRRangeBound, ""},
		{"string label 4", func(p map[int64]any) { p[PayloadLabelMmrEnd] = "63" }, ErrMMRRangeBound, ""},
		{"bstr label 4", func(p map[int64]any) { p[PayloadLabelMmrEnd] = []byte{63} }, ErrMMRRangeBound, ""},
		{"null label 3", func(p map[int64]any) { p[PayloadLabelMmrStart] = nil }, ErrMMRRangeBound, ""},
		{"null label 4", func(p map[int64]any) { p[PayloadLabelMmrEnd] = nil }, ErrMMRRangeBound, ""},
		{"tag-2 bignum label 3", func(p map[int64]any) { p[PayloadLabelMmrStart] = bignum2 }, nil, "tag"},
		{"tag-2 bignum label 4", func(p map[int64]any) { p[PayloadLabelMmrEnd] = bignum2 }, nil, "tag"},
		{"start > end", func(p map[int64]any) {
			p[PayloadLabelMmrStart] = uint64(64)
			p[PayloadLabelMmrEnd] = uint64(63)
		}, ErrMMRRangeInverted, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := rangeTestPayload(t)
			c.mutate(p)
			_, err := ParseCertificate(rangeTestCertWithPayload(t, p))
			require.Error(t, err)
			if c.wantIs != nil {
				require.ErrorIs(t, err, c.wantIs)
			} else {
				require.ErrorContains(t, err, c.wantText)
				require.NotErrorIs(t, err, ErrMMRRangeBound)
			}
		})
	}

	t.Run("control: unmutated payload parses", func(t *testing.T) {
		info, err := ParseCertificate(rangeTestCertWithPayload(t, rangeTestPayload(t)))
		require.NoError(t, err)
		require.Equal(t, uint64(0), info.MMRStart)
		require.Equal(t, uint64(63), info.MMREnd)
	})

	t.Run("start == end is accepted", func(t *testing.T) {
		info, err := ParseCertificate(rangeTestCert(t, 7, 7))
		require.NoError(t, err)
		require.Equal(t, uint64(7), info.MMRStart)
		require.Equal(t, uint64(7), info.MMREnd)
	})
}

// TestBuildDelegationToBeSigned_RejectsWhatParseRejects pins that the
// builder never emits a certificate ParseCertificate refuses: labels 3 and
// 4 are written only with a log id, and the range must not be inverted.
func TestBuildDelegationToBeSigned_RejectsWhatParseRejects(t *testing.T) {
	dk, err := NewDelegatedCoseKey(Secp256r1, make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)
	input := func(logID string, start, end uint64) DelegationInput {
		return DelegationInput{
			LogID:        logID,
			MmrStart:     start,
			MmrEnd:       end,
			DelegatedKey: dk,
			DelegationID: make([]byte, 16),
		}
	}

	_, err = BuildDelegationToBeSigned(Secp256r1, make([]byte, 16), input("", 0, 63))
	require.ErrorIs(t, err, ErrLogIDRequired)

	_, err = BuildDelegationToBeSigned(Secp256r1, make([]byte, 16), input(rangeTestLogID, 64, 63))
	require.ErrorIs(t, err, ErrMMRRangeInverted)

	_, err = BuildDelegationToBeSigned(Secp256r1, make([]byte, 16), input(rangeTestLogID, math.MaxUint64, 0))
	require.ErrorIs(t, err, ErrMMRRangeInverted)
}

func TestValidateMMRRange(t *testing.T) {
	require.NoError(t, ValidateMMRRange(0, 0))
	require.NoError(t, ValidateMMRRange(7, 7))
	require.NoError(t, ValidateMMRRange(0, math.MaxUint64))
	require.ErrorIs(t, ValidateMMRRange(1, 0), ErrMMRRangeInverted)
	require.ErrorIs(t, ValidateMMRRange(math.MaxUint64, math.MaxUint64-1), ErrMMRRangeInverted)
}
