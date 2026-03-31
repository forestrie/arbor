package scout

import (
	"net/url"
	"testing"
)

func TestParseFindIndexPath(t *testing.T) {
	testCases := []struct {
		name           string
		path           string
		operation      string
		expectedLog    string
		expectedTarget string
		expectError    bool
	}{
		{
			name:           "valid appid path",
			path:           "/api/logs/test-log/find-appid/1234567890abcdef",
			operation:      "appid",
			expectedLog:    "test-log",
			expectedTarget: "1234567890abcdef",
			expectError:    false,
		},
		{
			name:           "valid extrabytes path",
			path:           "/api/logs/my-log/find-extrabytes/abcdef123456",
			operation:      "extrabytes",
			expectedLog:    "my-log",
			expectedTarget: "abcdef123456",
			expectError:    false,
		},
		{
			name:        "invalid prefix",
			path:        "/wrong/logs/test-log/find-appid/1234",
			operation:   "appid",
			expectError: true,
		},
		{
			name:        "missing logID",
			path:        "/api/logs//find-appid/1234",
			operation:   "appid",
			expectError: true,
		},
		{
			name:        "missing target",
			path:        "/api/logs/test-log/find-appid/",
			operation:   "appid",
			expectError: true,
		},
		{
			name:        "wrong operation",
			path:        "/api/logs/test-log/find-wrong/1234",
			operation:   "appid",
			expectError: true,
		},
		{
			name:        "too few parts",
			path:        "/api/logs/test-log",
			operation:   "appid",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logID, target, err := parseFindIndexPath(tc.path, tc.operation)

			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if logID != tc.expectedLog {
				t.Errorf("expected logID %q, got %q", tc.expectedLog, logID)
			}

			if target != tc.expectedTarget {
				t.Errorf("expected target %q, got %q", tc.expectedTarget, target)
			}
		})
	}
}

func TestParseQueryParams(t *testing.T) {
	testCases := []struct {
		name        string
		query       string
		expectError bool
		expected    FindIndexParams
	}{
		{
			name:  "all parameters",
			query: "mmr-index=100&massif-range=5&idtimestamp=0x123456789abcdef0",
			expected: FindIndexParams{
				MinMMRIndex: uintPtr(100),
				MassifRange: 5,
				IDTimestamp: uintPtr(0x123456789abcdef0),
			},
		},
		{
			name:  "only required parameter",
			query: "massif-range=3",
			expected: FindIndexParams{
				MassifRange: 3,
			},
		},
		{
			name:  "with mmr index only",
			query: "massif-range=1&mmr-index=50",
			expected: FindIndexParams{
				MinMMRIndex: uintPtr(50),
				MassifRange: 1,
			},
		},
		{
			name:        "missing massif-range",
			query:       "mmr-index=100",
			expectError: true,
		},
		{
			name:        "zero massif-range",
			query:       "massif-range=0",
			expectError: true,
		},
		{
			name:        "invalid mmr-index",
			query:       "massif-range=1&mmr-index=invalid",
			expectError: true,
		},
		{
			name:        "invalid massif-range",
			query:       "massif-range=invalid",
			expectError: true,
		},
		{
			name:        "invalid idtimestamp",
			query:       "massif-range=1&idtimestamp=invalid",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			values, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatalf("failed to parse query: %v", err)
			}

			params, err := parseQueryParams(values)

			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if params.MassifRange != tc.expected.MassifRange {
				t.Errorf("expected MassifRange %d, got %d", tc.expected.MassifRange, params.MassifRange)
			}

			if !equalUintPtr(params.MinMMRIndex, tc.expected.MinMMRIndex) {
				t.Errorf("expected MinMMRIndex %v, got %v", tc.expected.MinMMRIndex, params.MinMMRIndex)
			}

			if !equalUintPtr(params.IDTimestamp, tc.expected.IDTimestamp) {
				t.Errorf("expected IDTimestamp %v, got %v", tc.expected.IDTimestamp, params.IDTimestamp)
			}
		})
	}
}

func TestDecodeLogID(t *testing.T) {
	testCases := []struct {
		name        string
		logID       string
		expected    []byte
		expectError bool
	}{
		{
			name:     "valid hex without prefix",
			logID:    "1234567890abcdef",
			expected: []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef},
		},
		{
			name:     "valid hex with 0x prefix",
			logID:    "0x1234567890abcdef",
			expected: []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef},
		},
		{
			name:     "empty string",
			logID:    "",
			expected: []byte{},
		},
		{
			name:        "invalid hex",
			logID:       "invalid",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := decodeLogID(tc.logID)

			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if !bytesEqual(result, tc.expected) {
					t.Errorf("expected %x, got %x", tc.expected, result)
				}
			}
		})
	}
}

func TestDecodeAndValidateAppID(t *testing.T) {
	testCases := []struct {
		name        string
		appID       string
		expected    []byte
		expectError bool
	}{
		{
			name:     "valid 32-byte hex",
			appID:    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expected: make([]byte, 32),
		},
		{
			name:     "valid with 0x prefix",
			appID:    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expected: make([]byte, 32),
		},
		{
			name:        "too short",
			appID:       "1234567890abcdef",
			expectError: true,
		},
		{
			name:        "too long",
			appID:       "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00",
			expectError: true,
		},
		{
			name:        "invalid hex characters",
			appID:       "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
			expectError: true,
		},
		{
			name:        "empty",
			appID:       "",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := decodeAndValidateAppID(tc.appID)

			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(result) != 32 {
					t.Errorf("expected 32 bytes, got %d", len(result))
				}
			}
		})
	}
}

func TestDecodeAndValidateExtraBytes(t *testing.T) {
	testCases := []struct {
		name        string
		extraBytes  string
		expected    []byte
		expectError bool
	}{
		{
			name:       "valid 24-byte hex",
			extraBytes: "1234567890abcdef1234567890abcdef1234567890abcdef",
			expected:   make([]byte, 24),
		},
		{
			name:       "valid with 0x prefix",
			extraBytes: "0x1234567890abcdef1234567890abcdef1234567890abcdef",
			expected:   make([]byte, 24),
		},
		{
			name:        "too short",
			extraBytes:  "1234567890abcdef",
			expectError: true,
		},
		{
			name:        "too long",
			extraBytes:  "1234567890abcdef1234567890abcdef1234567890abcdef00",
			expectError: true,
		},
		{
			name:        "invalid hex characters",
			extraBytes:  "gggggggggggggggggggggggggggggggggggggggggggggggg",
			expectError: true,
		},
		{
			name:        "empty",
			extraBytes:  "",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := decodeAndValidateExtraBytes(tc.extraBytes)

			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(result) != 24 {
					t.Errorf("expected 24 bytes, got %d", len(result))
				}
			}
		})
	}
}

func TestParseHexUint64(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expected    uint64
		expectError bool
	}{
		{
			name:     "valid hex without prefix",
			input:    "123456789abcdef0",
			expected: 0x123456789abcdef0,
		},
		{
			name:     "valid hex with 0x prefix",
			input:    "0x123456789abcdef0",
			expected: 0x123456789abcdef0,
		},
		{
			name:     "zero",
			input:    "0",
			expected: 0,
		},
		{
			name:     "max uint64",
			input:    "ffffffffffffffff",
			expected: 0xffffffffffffffff,
		},
		{
			name:        "invalid hex",
			input:       "invalid",
			expectError: true,
		},
		{
			name:        "too large",
			input:       "10000000000000000", // 17 hex digits
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseHexUint64(tc.input)

			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tc.expected {
					t.Errorf("expected %x, got %x", tc.expected, result)
				}
			}
		})
	}
}

func TestComputeStartMassifIndex(t *testing.T) {
	testCases := []struct {
		name        string
		minMMRIndex *uint64
		expected    uint64
	}{
		{
			name:     "nil mmr index",
			expected: 0,
		},
		{
			name:        "zero mmr index",
			minMMRIndex: uintPtr(0),
			expected:    0,
		},
		{
			name:        "small mmr index",
			minMMRIndex: uintPtr(100),
			expected:    0, // 100 / 1024 = 0
		},
		{
			name:        "large mmr index",
			minMMRIndex: uintPtr(2048),
			expected:    2, // 2048 / 1024 = 2
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := computeStartMassifIndex(tc.minMMRIndex)
			if result != tc.expected {
				t.Errorf("expected %d, got %d", tc.expected, result)
			}
		})
	}
}

// Helper functions for tests

func uintPtr(v uint64) *uint64 {
	return &v
}

func equalUintPtr(a, b *uint64) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
