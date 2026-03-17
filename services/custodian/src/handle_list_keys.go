package custodian

import (
	"encoding/json"
	"net/http"
)

// ListKeysRequest is the body for POST /api/keys/list.
type ListKeysRequest struct {
	Labels    map[string]string `json:"labels"`              // Label key-value pairs to match
	Predicate string           `json:"predicate,omitempty"` // "and" (all must match) or "or" (any must match); default "and"
}

// ListKeysResponse is the response for POST /api/keys/list.
type ListKeysResponse struct {
	Keys []KeyListEntry `json:"keys"`
}

// handleListKeys implements POST /api/keys/list — list keys matching labels and predicate.
// Normal app token required.
func (a *API) handleListKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if !a.RequireNormalApp(w, r) {
		return
	}
	var req ListKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "invalid JSON")
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
	a.writeJSON(w, http.StatusOK, ListKeysResponse{Keys: entries})
}
