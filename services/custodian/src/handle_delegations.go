package custodian

import (
	"net/http"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// handleDelegations implements POST /api/delegations (local custody sign only).
func (a *API) handleDelegations(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/delegations" {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
		return
	}
	if r.Method != http.MethodPost {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if !a.RequireNormalApp(w, r) {
		return
	}

	var req delegationcert.DelegationIssueRequest
	if !a.readCBORBody(w, r, &req) {
		return
	}

	resp, err := a.issueDelegationForLog(r.Context(), &req)
	if err != nil {
		st := delegationIssueHTTPStatus(err)
		title := "internal error"
		switch st {
		case http.StatusBadRequest:
			title = "bad request"
		case http.StatusNotFound:
			title = "not found"
		}
		if st == 0 {
			st = http.StatusInternalServerError
		}
		if st >= http.StatusInternalServerError {
			a.Logger.Error("issue delegation", "error", err)
		}
		a.writeProblem(w, r, st, "about:blank", title, err.Error())
		return
	}

	a.writeCBOR(w, http.StatusOK, resp)
}
