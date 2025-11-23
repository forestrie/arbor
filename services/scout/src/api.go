package scout

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	cborcodec "github.com/datatrails/go-datatrails-common/cbor"
)

// ProblemDetail follows the RFC 7807 problem details pattern.
type ProblemDetail struct {
	Type   string `json:"type" cbor:"type"`
	Title  string `json:"title" cbor:"title"`
	Status int    `json:"status" cbor:"status"`
	Detail string `json:"detail,omitempty" cbor:"detail,omitempty"`
}

const (
	cborContentType        = "application/cbor"
	problemDetailsCBORType = "application/problem+cbor"
	problemDetailsJSONType = "application/problem+json"
)

// API provides the CBOR HTTP API surface for scout.
type API struct {
	Logger *slog.Logger
	CBOR   cborcodec.CBORCodec
}

func NewAPI(logger *slog.Logger) (API, error) {
	encOpts := cborcodec.NewDeterministicEncOpts()
	decOpts := cborcodec.NewDeterministicDecOpts()
	codec, err := cborcodec.NewCBORCodec(encOpts, decOpts)
	if err != nil {
		return API{}, err
	}
	return API{Logger: logger, CBOR: codec}, nil
}

// RegisterRoutes wires the scout API endpoints onto the provided mux.
//
// The HeadIndex endpoint is served at:
//
//	/api/logs/{logId}/head-index
func (a API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/logs/", a.handleHeadIndex)
}

// handleHeadIndex implements the HeadIndex endpoint.
//
// The logId is taken from the request path using the scheme:
//
//	/api/logs/{logId}/head-index
//
// For now the implementation is a stub that always returns mmrIndex = 0.
func (a API) handleHeadIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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

// writeProblem writes a problem-details response in CBOR or JSON.
func (a API) writeProblem(w http.ResponseWriter, r *http.Request, status int, typ, title, detail string) {
	pd := ProblemDetail{
		Type:   typ,
		Title:  title,
		Status: status,
		Detail: detail,
	}

	accept := r.Header.Get("Accept")
	if acceptsJSON(accept) {
		w.Header().Set("Content-Type", problemDetailsJSONType)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(pd)
		return
	}

	b, err := a.CBOR.MarshalCBOR(pd)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": http.StatusInternalServerError})
		return
	}

	w.Header().Set("Content-Type", problemDetailsCBORType)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func acceptsJSON(accept string) bool {
	return accept == "" || accept == "*/*" || accept == "application/json" || accept == problemDetailsJSONType
}
