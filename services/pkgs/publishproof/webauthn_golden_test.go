package publishproof

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

const webauthnGoldenPath = "testdata/webauthn-real-authenticator-golden.json"

// webauthnGolden is the subset of the capture JSON this module consumes.
// The fixture was captured from a REAL platform authenticator via the
// thinker ceremony (delegateSealingWebauthn driven by scribe-ui's dev-only
// /goldens harness, plan-2608-13 Phase 5.1); the source of truth is canopy
// delegation-cose testdata/ (same file). Regeneration is a deliberate act —
// re-run the harness with a real authenticator.
type webauthnGolden struct {
	Authenticator string `json:"authenticator"`
	LogIDHex      string `json:"logIdHex"`
	MMRStart      string `json:"mmrStart"`
	MMREnd        string `json:"mmrEnd"`
	DelegatedKeyX string `json:"delegatedKeyX"`
	DelegatedKeyY string `json:"delegatedKeyY"`
	RootX         string `json:"rootX"`
	RootY         string `json:"rootY"`
	Onchain       struct {
		ProtectedHeader   string `json:"protectedHeader"`
		Signature         string `json:"signature"`
		AuthenticatorData string `json:"authenticatorData"`
		ClientDataJSON    string `json:"clientDataJSON"`
		ChallengeIndex    string `json:"challengeIndex"`
		TypeIndex         string `json:"typeIndex"`
	} `json:"onchain"`
}

func loadWebauthnGolden(t *testing.T) webauthnGolden {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(webauthnGoldenPath))
	require.NoError(t, err)
	var g webauthnGolden
	require.NoError(t, json.Unmarshal(raw, &g))
	return g
}

func goldenHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func goldenUint(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	require.NoError(t, err)
	return v
}

// goldenProof rebuilds the delegationcert.OnchainDelegationProof exactly as
// the delegation coordinator emits it for this capture.
func goldenProof(t *testing.T, g webauthnGolden) *delegationcert.OnchainDelegationProof {
	t.Helper()
	indices := make([]byte, 16)
	binary.BigEndian.PutUint64(indices[:8], goldenUint(t, g.Onchain.ChallengeIndex))
	binary.BigEndian.PutUint64(indices[8:], goldenUint(t, g.Onchain.TypeIndex))
	return &delegationcert.OnchainDelegationProof{
		ProtectedHeader: goldenHex(t, g.Onchain.ProtectedHeader),
		DelegationKey: append(
			goldenHex(t, g.DelegatedKeyX), goldenHex(t, g.DelegatedKeyY)...),
		MMRStart:  goldenUint(t, g.MMRStart),
		MMREnd:    goldenUint(t, g.MMREnd),
		Signature: goldenHex(t, g.Onchain.Signature),
		AlgData: [][]byte{
			goldenHex(t, g.Onchain.AuthenticatorData),
			goldenHex(t, g.Onchain.ClientDataJSON),
			indices,
		},
	}
}

// TestWebauthnGoldenAssertionVerifies proves the captured assertion in Go,
// independently of the TS and Solidity verifiers: challenge binding
// (clientDataJSON.challenge == base64url(sha256(Sig_structure)) at the
// recorded index), type binding, UP|UV flags, and the P-256 signature over
// authenticatorData || sha256(clientDataJSON) against the passkey root.
func TestWebauthnGoldenAssertionVerifies(t *testing.T) {
	g := loadWebauthnGolden(t)

	logIDBytes := goldenHex(t, g.LogIDHex)
	var logID [32]byte
	copy(logID[32-len(logIDBytes):], logIDBytes) // 16 bytes right-aligned

	payload := []byte(delegationcert.OnchainDelegationDomain)
	payload = append(payload, logID[:]...)
	payload = binary.BigEndian.AppendUint64(payload, goldenUint(t, g.MMRStart))
	payload = binary.BigEndian.AppendUint64(payload, goldenUint(t, g.MMREnd))
	payload = append(payload, goldenHex(t, g.DelegatedKeyX)...)
	payload = append(payload, goldenHex(t, g.DelegatedKeyY)...)

	challenge := sha256.Sum256(
		SigStructure(goldenHex(t, g.Onchain.ProtectedHeader), payload))
	wantChallenge := `"challenge":"` +
		base64.RawURLEncoding.EncodeToString(challenge[:]) + `"`

	clientDataJSON := string(goldenHex(t, g.Onchain.ClientDataJSON))
	challengeIndex := int(goldenUint(t, g.Onchain.ChallengeIndex))
	require.True(t,
		strings.HasPrefix(clientDataJSON[challengeIndex:], wantChallenge),
		"clientDataJSON does not bind this capture's Sig_structure challenge")
	typeIndex := int(goldenUint(t, g.Onchain.TypeIndex))
	require.True(t,
		strings.HasPrefix(clientDataJSON[typeIndex:], `"type":"webauthn.get"`))

	authenticatorData := goldenHex(t, g.Onchain.AuthenticatorData)
	require.GreaterOrEqual(t, len(authenticatorData), 37)
	require.Equal(t, byte(0x05), authenticatorData[32]&0x05,
		"real capture must carry UP and UV")

	clientDataHash := sha256.Sum256([]byte(clientDataJSON))
	digest := sha256.Sum256(append(
		append([]byte{}, authenticatorData...), clientDataHash[:]...))
	rootKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(goldenHex(t, g.RootX)),
		Y:     new(big.Int).SetBytes(goldenHex(t, g.RootY)),
	}
	signature := goldenHex(t, g.Onchain.Signature)
	require.Len(t, signature, 64)
	require.True(t, ecdsa.Verify(rootKey, digest[:],
		new(big.Int).SetBytes(signature[:32]),
		new(big.Int).SetBytes(signature[32:])),
		"real authenticator signature failed against the captured root")
	require.Equal(t, signature,
		delegationcert.NormalizeES256SignatureLowS(signature),
		"captured signature must already be low-s normalized")
}

// TestWebauthnGoldenReceiptRoundTrip pins the producer/consumer contract on
// the real bytes: the proof CBOR embeds in a sealed checkpoint's unprotected
// header, the decode lifts the 3-element algData, and the calldata encode /
// decode round-trips it unchanged.
func TestWebauthnGoldenReceiptRoundTrip(t *testing.T) {
	g := loadWebauthnGolden(t)
	onchain := goldenProof(t, g)
	raw, err := cbor.Marshal(onchain)
	require.NoError(t, err)

	sealer := newFixtureSealer(t)
	proof := ConsistencyProof{
		TreeSize1:  0,
		TreeSize2:  1,
		Paths:      [][][32]byte{},
		RightPeaks: [][32]byte{bytes32FromLow(t, "11")},
	}
	encoded, err := massifs.SignCheckpointReceipt(
		sealer.coseSigner, toProfileProof(proof), [][]byte{make([]byte, 32)},
		massifs.WithUnprotectedExtras(
			map[int64]cbor.RawMessage{massifs.SealDelegationProofLabel: raw}))
	require.NoError(t, err)

	receipt, err := DecodeCheckpointReceipt(encoded)
	require.NoError(t, err)
	require.Equal(t, onchain.AlgData, receipt.DelegationProof.AlgData)
	require.Equal(t, onchain.Signature, receipt.DelegationProof.Signature)

	calldata, err := EncodePublishCheckpoint(
		receipt,
		InclusionProof{Index: 0, Path: [][32]byte{}},
		[8]byte{},
		PublishGrant{
			Grant: big.NewInt(1), Request: big.NewInt(1), GrantData: []byte{},
		},
	)
	require.NoError(t, err)
	gotReceipt, _, _, _, err := DecodePublishCheckpoint(calldata)
	require.NoError(t, err)
	require.Equal(t, receipt, gotReceipt)
}
