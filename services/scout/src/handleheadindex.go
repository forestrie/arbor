package scout

import (
	"net/http"
	"strings"
)

// handleHeadIndex implements the HeadIndex endpoint.
//
// The logId is taken from the request path using the scheme:
//
//	/api/logs/{logId}/head-index
//
// For now the implementation is a stub that always returns mmrIndex = 0.
func (a API) handleHeadIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}

	const prefix = "/api/logs/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, prefix) // "{logId}/head-index"
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "head-index" {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
		return
	}

	logID := parts[0]

	resp := struct {
		LogID    string `json:"logId" cbor:"logId"`
		MMRIndex uint64 `json:"mmrIndex" cbor:"mmrIndex"`
	}{
		LogID:    logID,
		MMRIndex: 0,
	}

	data, err := a.CBOR.MarshalCBOR(resp)
	if err != nil {
		a.Logger.Error("failed to marshal CBOR response", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "encoding failure")
		return
	}

	w.Header().Set("Content-Type", cborContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
