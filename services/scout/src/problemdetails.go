package scout

import (
	"encoding/json"
	"net/http"
)

// ProblemDetail follows the RFC 7807 problem details pattern.
type ProblemDetail struct {
	Type   string `json:"type" cbor:"type"`
	Title  string `json:"title" cbor:"title"`
	Status int    `json:"status" cbor:"status"`
	Detail string `json:"detail,omitempty" cbor:"detail,omitempty"`
}

const (
	problemDetailsCBORType = "application/problem+cbor"
	problemDetailsJSONType = "application/problem+json"
)

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
