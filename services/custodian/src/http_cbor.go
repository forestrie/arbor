package custodian

import (
	"io"
	"net/http"
	"strings"
)

const (
	cborContentType      = "application/cbor"
	problemCBORType      = "application/problem+cbor"
	coseSign1ContentType = `application/cose; cose-type="cose-sign1"`
)

// requireCBORContentType returns false and writes 415 if the request with a body
// must be application/cbor.
func (a *API) requireCBORContentType(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		a.writeProblem(w, r, http.StatusUnsupportedMediaType, "about:blank", "unsupported media type", "Content-Type application/cbor required")
		return false
	}
	// Allow parameters e.g. application/cbor; charset=utf-8
	base := ct
	if idx := strings.Index(base, ";"); idx >= 0 {
		base = strings.TrimSpace(base[:idx])
	}
	if base != cborContentType {
		a.writeProblem(w, r, http.StatusUnsupportedMediaType, "about:blank", "unsupported media type", "Content-Type application/cbor required")
		return false
	}
	return true
}

func (a *API) readCBORBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if !a.requireCBORContentType(w, r) {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "could not read body")
		return false
	}
	if err := custodianCBORdm.Unmarshal(body, v); err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "invalid CBOR")
		return false
	}
	return true
}

func (a *API) writeCBOR(w http.ResponseWriter, status int, v any) {
	b, err := custodianCBORem.Marshal(v)
	if err != nil {
		a.Logger.Error("cbor marshal response", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", cborContentType)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (a *API) writeCOSESign1(w http.ResponseWriter, status int, sign1 []byte) {
	w.Header().Set("Content-Type", coseSign1ContentType)
	w.WriteHeader(status)
	_, _ = w.Write(sign1)
}
