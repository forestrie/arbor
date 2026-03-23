package custodian

import (
	"net/http"
)

// ProblemDetail follows RFC 7807 fields encoded as CBOR (application/problem+cbor).
type ProblemDetail struct {
	Type   string `cbor:"type"`
	Title  string `cbor:"title"`
	Status int    `cbor:"status"`
	Detail string `cbor:"detail,omitempty"`
}

// writeProblem writes a problem-details response as application/problem+cbor.
func (a *API) writeProblem(w http.ResponseWriter, r *http.Request, status int, typ, title, detail string) {
	_ = r // exclusive CBOR; no Accept negotiation
	pd := ProblemDetail{
		Type:   typ,
		Title:  title,
		Status: status,
		Detail: detail,
	}
	b, err := custodianCBORem.Marshal(pd)
	if err != nil {
		a.Logger.Error("cbor marshal problem", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", problemCBORType)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
