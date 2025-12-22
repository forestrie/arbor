package scout

import (
	"net/http"
)

// FindExtraBytesResponse represents the response structure for the find-extrabytes endpoint.
type FindExtraBytesResponse struct {
	LogID       []byte  `json:"logId" cbor:"logId"`
	ExtraBytes  []byte  `json:"extraBytes" cbor:"extraBytes"`
	IDTimestamp *uint64 `json:"idTimestamp,omitempty" cbor:"idTimestamp,omitempty"`
	MMRIndex    *uint64 `json:"mmrIndex,omitempty" cbor:"mmrIndex,omitempty"`
	MassifIndex uint64  `json:"massifIndex" cbor:"massifIndex"`
	Found       bool    `json:"found" cbor:"found"`
}

// handleFindExtraBytes implements the FindExtraBytes endpoint.
//
// The endpoint searches for entries with specific extra bytes within a log.
// URL pattern: /api/logs/{logId}/find-extrabytes/{extraBytes}?mmr-index={minMmrIndex}&massif-range={range}&idtimestamp={idTimestamp}
//
// Parameters:
//   - logId: The identifier of the log to search in
//   - extraBytes: A 24-byte hex-encoded extra bytes value to search for
//   - mmr-index (optional): Minimum mmrIndex to start the search from
//   - massif-range: Minimum number of massifs to search (must be >= 1)
//   - idtimestamp (optional): 64-bit integer encoded as hex string, optionally prefixed by epoch
//
// The idtimestamp parameter can be a 64-bit integer encoded as a hex string.
// If no epoch is specified, the default epoch is taken from the massif header
// implied by the `mmr-index`.
//
// The handler computes the starting massif index based on the provided
// `mmr-index` and ensures at least the specified number of massifs are searched.
// If the `mmr-index` is greater than the first index in the implied start
// massif, at least two massifs will be read.
//
// Response includes cache control headers indicating the response can be cached
// indefinitely since log entries are immutable.
func (a API) handleFindExtraBytes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}

	// Parse the URL path to extract logID and extraBytes
	logIDHex, extraBytesHex, err := parseFindIndexPath(r.URL.Path, "extrabytes")
	if err != nil {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
		return
	}

	// Decode and validate the logID
	logIDBytes, err := decodeLogID(logIDHex)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId", err.Error())
		return
	}

	// Decode and validate the extraBytes format (24-byte hex string)
	extraBytesDecoded, err := decodeAndValidateExtraBytes(extraBytesHex)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid extraBytes", err.Error())
		return
	}

	// Parse query parameters
	baseParams, err := parseQueryParams(r.URL.Query())
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid query parameters", err.Error())
		return
	}

	// Create find-specific parameters
	params := FindExtraBytesParams{
		FindIndexParams: baseParams,
		ExtraBytes:      extraBytesDecoded,
	}
	params.LogID = logIDBytes

	// Compute the starting massif index based on the optional mmr-index
	startMassifIndex := computeStartMassifIndex(params.MinMMRIndex)

	// TODO: Implement actual search logic
	// For now, return a stub response indicating not found
	response := FindExtraBytesResponse{
		LogID:       params.LogID,
		ExtraBytes:  params.ExtraBytes,
		IDTimestamp: params.IDTimestamp,
		MMRIndex:    nil, // Will be set when found
		MassifIndex: startMassifIndex,
		Found:       false,
	}

	// Write the response with appropriate cache headers
	if err := a.writeFindResponse(w, response); err != nil {
		a.Logger.Error("failed to write find extrabytes response", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "encoding failure")
		return
	}
}
