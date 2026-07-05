package publishproof

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLiveResolvePublicDomain resolves a real log against a live grants-bucket
// public domain — the anonymous, credential-free path ADR-0047 commits to.
// Opt-in (needs live lane data):
//
//	RESOLVE_LIVE_BASE_URL=https://pub-<hash>.r2.dev \
//	RESOLVE_LIVE_LOG_ID=<uuid> go test -run TestLiveResolvePublicDomain -v
func TestLiveResolvePublicDomain(t *testing.T) {
	base := os.Getenv("RESOLVE_LIVE_BASE_URL")
	logIDStr := os.Getenv("RESOLVE_LIVE_LOG_ID")
	if base == "" || logIDStr == "" {
		t.Skip("set RESOLVE_LIVE_BASE_URL and RESOLVE_LIVE_LOG_ID for the live resolution check")
	}

	store := NewPublicBucketGetter(base, nil)
	got, err := ResolveForestContract(t.Context(), store, testLogID(t, logIDStr))
	require.NoError(t, err)
	require.False(t, got.R.IsZero())
	require.NotZero(t, got.ChainID)
	t.Logf("resolved %s -> R=%s chainId=%d contract=%s",
		logIDStr, got.R, got.ChainID, got.Contract.Hex())
}
