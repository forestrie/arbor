package univocity

import (
	"encoding/json"
	"net/http"
)

// ProblemDetail follows the RFC 7807 problem details pattern (JSON).
type ProblemDetail struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

const problemDetailsJSONType = "application/problem+json"

func (a API) writeProblem(w http.ResponseWriter, r *http.Request, status int, typ, title, detail string) {
	pd := ProblemDetail{
		Type:   typ,
		Title:  title,
		Status: status,
		Detail: detail,
	}
	w.Header().Set("Content-Type", problemDetailsJSONType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(pd)
}
