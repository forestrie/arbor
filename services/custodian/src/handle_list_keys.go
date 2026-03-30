package custodian

import (
	"net/http"
	"net/url"
	"strings"
)

func listLabelsFromQuery(q url.Values) (labels map[string]string, predicate string, ok bool) {
	predicate = strings.TrimSpace(q.Get("predicate"))
	if predicate == "" {
		predicate = "and"
	}
	labels = make(map[string]string)
	for k, vals := range q {
		if strings.EqualFold(k, "predicate") {
			continue
		}
		if len(vals) == 0 {
			continue
		}
		v := strings.TrimSpace(vals[0])
		if v == "" {
			continue
		}
		labels[k] = v
	}
	if len(labels) == 0 {
		return nil, predicate, false
	}
	return labels, predicate, true
}

// handleListKeys implements GET and POST /api/keys/list — list keys matching labels and predicate.
// GET: labels from query parameters (excluding predicate); POST: CBOR body (unchanged).
// Normal app token required.
func (a *API) handleListKeys(w http.ResponseWriter, r *http.Request) {
	var req ListKeysRequest
	switch r.Method {
	case http.MethodGet:
		if !a.RequireNormalApp(w, r) {
			return
		}
		labels, predicate, ok := listLabelsFromQuery(r.URL.Query())
		if !ok {
			a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "at least one label query parameter required")
			return
		}
		req = ListKeysRequest{Labels: labels, Predicate: predicate}
	case http.MethodPost:
		if !a.RequireNormalApp(w, r) {
			return
		}
		if !a.readCBORBody(w, r, &req) {
			return
		}
	default:
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	predicate := req.Predicate
	if predicate == "" {
		predicate = "and"
	}
	if predicate != "and" && predicate != "or" {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "predicate must be 'and' or 'or'")
		return
	}
	if req.Labels == nil {
		req.Labels = make(map[string]string)
	}
	entries, err := a.ListKeysWithLabels(r.Context(), req.Labels, predicate)
	if err != nil {
		a.Logger.Error("failed to list keys", "error", err)
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank", "internal error", "list keys failed")
		return
	}
	if entries == nil {
		entries = []KeyListEntry{}
	}
	a.writeCBOR(w, http.StatusOK, ListKeysResponse{Keys: entries})
}
