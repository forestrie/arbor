package custodian

import (
	"errors"
	"io"
	"net/http"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
)

// handleDelegations implements POST /api/delegations (local sign or coordinator proxy).
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
	if !a.requireCBORContentType(w, r) {
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "could not read body")
		return
	}

	var req delegationcert.DelegationIssueRequest
	if err := custodianCBORdm.Unmarshal(body, &req); err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", "invalid CBOR")
		return
	}

	logIdHex, err := logIDHexFromWire(req.LogID)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "bad request", err.Error())
		return
	}

	ctx := r.Context()
	auth := bearerFromRequest(r)

	if a.coordinatorConfigured() && a.isWalletManagedLog(ctx, logIdHex) {
		a.proxyAndWriteDelegation(w, r, body, auth)
		return
	}

	resp, err := a.issueDelegationForLog(ctx, &req)
	if err != nil {
		if a.coordinatorConfigured() && errors.Is(err, ErrNoCustodianKeyForLogID) {
			a.proxyAndWriteDelegation(w, r, body, auth)
			return
		}
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

func (a *API) proxyAndWriteDelegation(w http.ResponseWriter, r *http.Request, body []byte, auth string) {
	resp, st, err := a.proxyDelegationIssue(r.Context(), body, auth)
	if err != nil {
		if st == 0 {
			st = http.StatusBadGateway
		}
		title := "bad gateway"
		if st == http.StatusServiceUnavailable {
			title = "service unavailable"
		}
		if st >= http.StatusInternalServerError {
			a.Logger.Error("coordinator delegation proxy", "error", err)
		}
		a.writeProblem(w, r, st, "about:blank", title, err.Error())
		return
	}
	a.writeCBOR(w, http.StatusOK, resp)
}
