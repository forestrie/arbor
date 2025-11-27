package scout

import (
	"net/http"
)

// FindAppIDResponse represents the response structure for the find-appid endpoint.
type FindAppIDResponse struct {
	LogID       []byte  `json:"logId" cbor:"logId"`
	AppID       []byte  `json:"appId" cbor:"appId"`
	MMRIndex    *uint64 `json:"mmrIndex,omitempty" cbor:"mmrIndex,omitempty"`
	MassifIndex uint64  `json:"massifIndex" cbor:"massifIndex"`
	Found       bool    `json:"found" cbor:"found"`
}

// handleFindAppID implements the FindAppID endpoint.
//
// The endpoint searches for entries with a specific application ID within a log.
// URL pattern: /api/logs/{logId}/find-appid/{appId}?fence-index={fenceIndex}&massif-range={range}
//
// Parameters:
//   - logId: The identifier of the log to search in
//   - appId: A 32-byte hex-encoded application identifier to search for
//   - fence-index (optional): Minimum mmrIndex to start the search from
//   - massif-range: Minimum number of massifs to search (must be >= 1)
//
// The handler computes the starting massif index based on the fence index and
// ensures at least the specified number of massifs are searched. If the fence
// index is greater than the first index in the implied start massif, at least
// two massifs will be read.
//
// Response includes cache control headers indicating the response can be cached
// indefinitely since log entries are immutable.
func (a API) handleFindAppID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}

	// Parse the URL path to extract logID and appID
	logIDHex, appIDHex, err := parseFindIndexPath(r.URL.Path, "appid")
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

	// Decode and validate the appID format (32-byte hex string)
	appIDBytes, err := decodeAndValidateAppID(appIDHex)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid appId", err.Error())
		return
	}

	// Parse query parameters
	baseParams, err := parseQueryParams(r.URL.Query())
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid query parameters", err.Error())
		return
	}

	// Create find-specific parameters
	params := FindAppIDParams{
		FindIndexParams: baseParams,
		AppID:           appIDBytes,
	}
	params.LogID = logIDBytes

	// Compute the starting massif index based on fence index
	startMassifIndex := computeStartMassifIndex(params.FenceIndex)

	// TODO: Implement actual search logic
	// For now, return a stub response indicating not found
	response := FindAppIDResponse{
		LogID:       params.LogID,
		AppID:       params.AppID,
		MMRIndex:    nil, // Will be set when found
		MassifIndex: startMassifIndex,
		Found:       false,
	}

	// Write the response with appropriate cache headers
	if err := a.writeFindResponse(w, response); err != nil {
		a.Logger.Error("failed to write find appid response", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "encoding failure")
		return
	}
}
