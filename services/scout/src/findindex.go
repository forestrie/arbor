package scout

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// FindIndexParams holds common parameters for find operations.
type FindIndexParams struct {
	LogID       []byte  // Decoded log ID bytes
	FenceIndex  *uint64 // Optional minimum mmrIndex to start search from
	MassifRange uint64  // Minimum number of massifs to search
	IDTimestamp *uint64 // Optional timestamp for find operations
}

// FindAppIDParams extends FindIndexParams with app-specific parameters.
type FindAppIDParams struct {
	FindIndexParams
	AppID []byte // 32-byte decoded app ID
}

// FindExtraBytesParams extends FindIndexParams with extra bytes specific parameters.
type FindExtraBytesParams struct {
	FindIndexParams
	ExtraBytes []byte // 24-byte decoded extra bytes
}

// parseFindIndexPath extracts the log ID and operation from a find index path.
// Expected path format: "/api/logs/{logId}/find-{operation}/{target}"
// Returns the hex-encoded logID and target strings for further processing.
func parseFindIndexPath(path, operation string) (logID, target string, err error) {
	prefix := "/api/logs/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", fmt.Errorf("invalid path prefix")
	}

	rest := strings.TrimPrefix(path, prefix) // "{logId}/find-{operation}/{target}"
	parts := strings.Split(rest, "/")

	expectedOperation := "find-" + operation
	if len(parts) != 3 || parts[0] == "" || parts[1] != expectedOperation || parts[2] == "" {
		return "", "", fmt.Errorf("invalid path format")
	}

	return parts[0], parts[2], nil
}

// decodeLogID decodes a hex-encoded log ID to bytes.
func decodeLogID(logIDHex string) ([]byte, error) {
	logIDHex = strings.TrimPrefix(logIDHex, "0x")
	logIDBytes, err := hex.DecodeString(logIDHex)
	if err != nil {
		return nil, fmt.Errorf("invalid logID hex encoding: %w", err)
	}
	return logIDBytes, nil
}

// parseQueryParams extracts common query parameters for find operations.
func parseQueryParams(values url.Values) (FindIndexParams, error) {
	var params FindIndexParams

	// Parse optional fence-index
	if fenceStr := values.Get("fence-index"); fenceStr != "" {
		fence, err := strconv.ParseUint(fenceStr, 10, 64)
		if err != nil {
			return params, fmt.Errorf("invalid fence-index: %w", err)
		}
		params.FenceIndex = &fence
	}

	// Parse massif-range (required)
	rangeStr := values.Get("massif-range")
	if rangeStr == "" {
		return params, fmt.Errorf("massif-range parameter is required")
	}
	massifRange, err := strconv.ParseUint(rangeStr, 10, 64)
	if err != nil {
		return params, fmt.Errorf("invalid massif-range: %w", err)
	}
	if massifRange == 0 {
		return params, fmt.Errorf("massif-range must be greater than 0")
	}
	params.MassifRange = massifRange

	// Parse optional idtimestamp
	if timestampStr := values.Get("idtimestamp"); timestampStr != "" {
		// Handle optional epoch prefix - for now we'll parse as hex
		// TODO: Implement epoch handling based on massif header
		timestamp, err := parseHexUint64(timestampStr)
		if err != nil {
			return params, fmt.Errorf("invalid idtimestamp: %w", err)
		}
		params.IDTimestamp = &timestamp
	}

	return params, nil
}

// parseHexUint64 parses a hex-encoded uint64, with or without 0x prefix.
func parseHexUint64(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	return strconv.ParseUint(s, 16, 64)
}

// decodeAndValidateAppID validates and decodes a 32-byte hex encoded appID.
func decodeAndValidateAppID(appID string) ([]byte, error) {
	appID = strings.TrimPrefix(appID, "0x")
	if len(appID) != 64 { // 32 bytes * 2 hex chars per byte
		return nil, fmt.Errorf("appID must be 32 bytes (64 hex characters), got %d", len(appID))
	}
	appIDBytes, err := hex.DecodeString(appID)
	if err != nil {
		return nil, fmt.Errorf("appID must be valid hex: %w", err)
	}
	return appIDBytes, nil
}

// decodeAndValidateExtraBytes validates and decodes a 24-byte hex encoded extraBytes.
func decodeAndValidateExtraBytes(extraBytes string) ([]byte, error) {
	extraBytes = strings.TrimPrefix(extraBytes, "0x")
	if len(extraBytes) != 48 { // 24 bytes * 2 hex chars per byte
		return nil, fmt.Errorf("extraBytes must be 24 bytes (48 hex characters), got %d", len(extraBytes))
	}
	extraBytesDecoded, err := hex.DecodeString(extraBytes)
	if err != nil {
		return nil, fmt.Errorf("extraBytes must be valid hex: %w", err)
	}
	return extraBytesDecoded, nil
}

// computeStartMassifIndex computes the first massif index to start the search from
// based on the fence index. This is a placeholder implementation.
func computeStartMassifIndex(fenceIndex *uint64) uint64 {
	if fenceIndex == nil {
		return 0
	}
	// TODO: Implement actual massif index computation based on fence index
	// For now, assume each massif contains 1024 entries
	return *fenceIndex / 1024
}

// setCacheControlHeaders sets cache control headers indicating the response
// can be cached indefinitely.
func setCacheControlHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("ETag", "\"immutable\"")
}

// writeFindResponse writes a successful find response in CBOR format.
func (a API) writeFindResponse(w http.ResponseWriter, response interface{}) error {
	data, err := a.CBOR.MarshalCBOR(response)
	if err != nil {
		return fmt.Errorf("failed to marshal CBOR response: %w", err)
	}

	setCacheControlHeaders(w)
	w.Header().Set("Content-Type", cborContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	return nil
}
