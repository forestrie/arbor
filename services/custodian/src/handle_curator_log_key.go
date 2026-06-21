package custodian

import (
	"errors"
	"net/http"
	"strings"
)

// handleCuratorLogKey implements GET /api/keys/curator/log-key?logId=...
// Normal app token required. Response: CBOR { keyId } (custody short id).
func (a *API) handleCuratorLogKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if !a.RequireNormalApp(w, r) {
		return
	}
	raw := strings.TrimSpace(r.URL.Query().Get("logId"))
	if raw == "" {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "logId query parameter required")
		return
	}
	keyID, err := a.ResolveCustodianKeyIDForLogID(r.Context(), raw)
	if err != nil {
		st := http.StatusBadRequest
		title := "bad request"
		if errors.Is(err, ErrNoCustodianKeyForLogID) {
			st = http.StatusNotFound
			title = "not found"
		}
		a.writeProblem(w, r, st, "about:blank", title, err.Error())
		return
	}
	a.writeCBOR(w, http.StatusOK, CuratorLogKeyResponse{KeyID: keyID})
}
