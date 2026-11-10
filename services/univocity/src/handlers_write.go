package univocity

import (
	"errors"
	"io"
	"net/http"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/fxamacker/cbor/v2"
)

const maxRequestBody = 512 * 1024

// postGrantRequest carries a creation grant (SCITT transparent statement),
// optionally the forest root it belongs to (the register path's
// bootstrap-logid), and the caller's intent: reserve (prepare) or commit
// (register-grant).
type postGrantRequest struct {
	RootLogID []byte `cbor:"rootLogId,omitempty"`
	Statement []byte `cbor:"statement"`
	Intent    string `cbor:"intent"`
}

// postGrantResponse reports the claim a grant post holds.
type postGrantResponse struct {
	State     string `cbor:"state"`
	ExpiresAt int64  `cbor:"expiresAt,omitempty"`
}

func readBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
}

func (a API) handlePostGenesis(w http.ResponseWriter, r *http.Request) {
	if !a.requireToken(w, r) {
		return
	}
	if a.Store == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
			"store unavailable", "grant store not configured")
		return
	}
	pathR, ok := logIDFromPathValue(r.PathValue("logId"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId", "")
		return
	}
	body, err := readBody(r)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "read body failed", err.Error())
		return
	}
	if err := validateGenesisPostVersion(body); err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid genesis", err.Error())
		return
	}
	doc, err := parseGenesisDoc(body)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid genesis", err.Error())
		return
	}
	if doc.Forest.R != pathR {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank",
			"genesis mismatch", "bootstrap-logid does not match path log-id")
		return
	}
	if err := a.verifyGenesisAnchor(r, doc); err != nil {
		if errors.Is(err, errGenesisKeyMismatch) {
			a.writeProblem(w, r, http.StatusUnprocessableEntity, "about:blank",
				"genesis key mismatch", err.Error())
			return
		}
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank",
			"anchor verification failed", err.Error())
		return
	}
	// Claim-first (plan-2607-10 D4): the R->R self-index is the atomic
	// global-uniqueness claim and must precede the genesis object, mirroring
	// handlePostGrant — a logId already bound as another forest's subject
	// must not acquire a genesis document. Both writes are idempotent, so a
	// crash between them is repaired by retry.
	claimed, existing, err := a.Store.IndexCreate(r.Context(), doc.Forest.R, doc.Forest.R)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank",
			"index create failed", err.Error())
		return
	}
	// Cross-forest conflict is 422, NOT 409: canopy's genesis-forward maps
	// every 409 to idempotent "exists" (univocity-genesis-client.ts), so a
	// 409 here would report onboarding success with no genesis stored. 409
	// stays reserved for the same-R "genesis exists" retry signal below
	// (plan-2607-11 R1).
	if !claimed && existing != doc.Forest.R {
		a.writeProblem(w, r, http.StatusUnprocessableEntity, "about:blank",
			"logId belongs to another forest",
			"global logId->R uniqueness violated")
		return
	}
	created, err := a.Store.PutGenesisIfAbsent(r.Context(), doc.Forest.R, body)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "store genesis failed", err.Error())
		return
	}
	if !created {
		a.writeProblem(w, r, http.StatusConflict, "about:blank",
			"genesis exists", "genesis.cbor already exists for this forest")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (a API) handleGetGenesis(w http.ResponseWriter, r *http.Request) {
	if a.Store == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
			"store unavailable", "grant store not configured")
		return
	}
	pathR, ok := logIDFromPathValue(r.PathValue("logId"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId", "")
		return
	}
	body, err := a.Store.GetGenesis(r.Context(), pathR)
	if err != nil {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "genesis not found", "")
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// errGenesisKeyMismatch reports a genesis document whose key is not the
// contract's bootstrap key.
var errGenesisKeyMismatch = errors.New("genesis key differs from the contract's bootstrapConfig()")

// verifyGenesisAnchor requires genesis.key == the contract's bootstrapConfig()
// for the forest's chain/contract: the root's key comes only from the
// contract (devdocs ADR-0075 decision 7), so a genesis naming another key is
// refused, and one whose contract cannot be read cannot be checked.
func (a API) verifyGenesisAnchor(r *http.Request, doc GenesisDoc) error {
	if a.Pool == nil {
		return errors.New("rpc pool not configured")
	}
	reader, err := a.Pool.Reader(doc.Forest.ChainID, doc.Forest.Contract)
	if err != nil {
		return err
	}
	bootAlg, bootKey, err := a.bootstrapConfig(r.Context(), doc.Forest, reader)
	if err != nil {
		return err
	}
	if !bootstrapKeysEqual(doc.Alg, doc.GenesisKeyBytes(), bootAlg, bootKey) {
		return errGenesisKeyMismatch
	}
	return nil
}

func (a API) handlePostGrant(w http.ResponseWriter, r *http.Request) {
	if !a.requireToken(w, r) {
		return
	}
	if a.Store == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
			"store unavailable", "grant store not configured")
		return
	}
	body, err := readBody(r)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "read body failed", err.Error())
		return
	}
	var req postGrantRequest
	if err := cbor.Unmarshal(body, &req); err != nil || len(req.Statement) == 0 ||
		(req.Intent != intentReserve && req.Intent != intentCommit) {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid request",
			"expect CBOR { statement, intent: reserve|commit, rootLogId? }")
		return
	}
	ts, err := decodeTransparentStatement(req.Statement)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid grant", err.Error())
		return
	}
	subject := ts.Grant.LogID

	root, ok := a.deriveForestRoot(r, req, ts)
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank",
			"forest unknown", "rootLogId required or owner not yet registered")
		return
	}
	forest, err := a.loadForest(r.Context(), root)
	if err != nil {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank",
			"forest genesis missing", err.Error())
		return
	}
	reader, err := a.Pool.Reader(forest.ChainID, forest.Contract)
	if err != nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
			"chain not configured", err.Error())
		return
	}
	if err := a.verifyGrantChain(r.Context(), forest, reader, ts); err != nil {
		a.writeProblem(w, r, http.StatusUnprocessableEntity, "about:blank",
			"grant chain invalid", err.Error())
		return
	}
	class, err := grantClassFromFlags(ts.Grant.Flags)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank",
			"invalid grant class", err.Error())
		return
	}
	if req.Intent == intentCommit && !a.requireOwnerAnchored(w, r, forest, reader, ts.Grant) {
		return
	}
	var res claimResult
	if req.Intent == intentReserve {
		res, err = a.reserveClaim(r.Context(), root, ts)
	} else {
		res, err = a.commitClaim(r.Context(), root, ts, class)
	}
	switch {
	case errors.Is(err, errGrantAlreadyClaimed):
		a.writeProblem(w, r, http.StatusConflict, "about:blank",
			"grant-already-claimed", "a different create grant has claimed log "+subject.String())
		return
	case errors.Is(err, errLogInOtherForest):
		a.writeProblem(w, r, http.StatusConflict, "about:blank",
			"logId belongs to another forest", err.Error())
		return
	case err != nil:
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "claim failed", err.Error())
		return
	}
	a.writeClaim(w, r, res)
}

// requireOwnerAnchored refuses to commit a grant whose owner is not anchored:
// a committed grant is sequenced at once, and its leaf can only be anchored
// by a published checkpoint of an anchored owner (devdocs ADR-0075
// decision 8). canopy-api refuses first; this is the backstop.
func (a API) requireOwnerAnchored(
	w http.ResponseWriter,
	r *http.Request,
	forest ForestEntry,
	reader ChainReader,
	g Grant,
) bool {
	if g.LogID == forest.R {
		return true // the root's own grant: its key is the contract's
	}
	owner, err := a.authorityIn(r.Context(), forest, reader, g.OwnerLogID, 0)
	if err != nil {
		a.writeAuthorityError(w, r, err)
		return false
	}
	switch {
	case owner.usable():
		return true
	case owner.State == stateConflicted || owner.blockedByConflict:
		a.writeProblem(w, r, http.StatusConflict, "about:blank", "authority-conflict",
			"owner "+g.OwnerLogID.String()+" is conflicted or below a conflicted log; it will never anchor")
	case !owner.BlockedBy.IsZero():
		a.writeProblem(w, r, http.StatusConflict, "about:blank", "owner-not-anchored",
			"owner "+g.OwnerLogID.String()+" waits on "+owner.BlockedBy.String()+" to anchor; commit once it is anchored")
	default:
		a.writeProblem(w, r, http.StatusConflict, "about:blank", "owner-not-anchored",
			"owner "+g.OwnerLogID.String()+" is "+owner.State+"; commit once it is anchored")
	}
	return false
}

func (a API) writeClaim(w http.ResponseWriter, r *http.Request, res claimResult) {
	resp := postGrantResponse{State: res.state}
	if res.state == stateReserved {
		resp.ExpiresAt = res.expiresAt.Unix()
	}
	out, err := canonicalCBOR.Marshal(resp)
	if err != nil {
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank",
			"encode failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	if res.created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_, _ = w.Write(out)
}

// deriveForestRoot determines the forest root R for a posted grant: explicit
// rootLogId, else self (root grant), else the owner's indexed forest.
func (a API) deriveForestRoot(
	r *http.Request,
	req postGrantRequest,
	ts TransparentStatement,
) (logid.UUID, bool) {
	if len(req.RootLogID) > 0 {
		root, ok := wireFrom(req.RootLogID)
		return root, ok
	}
	if ts.Grant.OwnerLogID == ts.Grant.LogID {
		return ts.Grant.LogID, true
	}
	if a.Store == nil {
		return logid.Zero, false
	}
	root, found, err := a.Store.IndexGet(r.Context(), ts.Grant.OwnerLogID)
	if err != nil {
		return logid.Zero, false
	}
	if !found {
		// An owner that is itself only reserved is found by its reservation.
		root, found, err = a.liveReservationRoot(r.Context(), ts.Grant.OwnerLogID)
		if err != nil || !found {
			return logid.Zero, false
		}
	}
	return root, true
}

func (a API) handleDeleteGrant(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminToken(w, r) {
		return
	}
	if a.Store == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank", "store unavailable", "")
		return
	}
	root, ok := logIDFromPathValue(r.PathValue("logId"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId", "")
		return
	}
	subject, ok := logIDFromPathValue(r.PathValue("subject"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid subject", "")
		return
	}
	if err := a.Store.DeleteGrant(r.Context(), root, subject); err != nil {
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "delete grant failed", err.Error())
		return
	}
	if err := a.Store.DeleteIndex(r.Context(), subject); err != nil {
		a.Logger.Warn("delete index failed", "subject", subject.String(), "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a API) handleDeleteForest(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminToken(w, r) {
		return
	}
	if a.Store == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank", "store unavailable", "")
		return
	}
	root, ok := logIDFromPathValue(r.PathValue("logId"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId", "")
		return
	}
	if err := a.Store.DeleteGenesis(r.Context(), root); err != nil {
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "delete genesis failed", err.Error())
		return
	}
	if err := a.Store.DeleteIndex(r.Context(), root); err != nil {
		a.Logger.Warn("delete root index failed", "R", root.String(), "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func wireFrom(b []byte) (logid.UUID, bool) {
	id, err := logid.FromBytes(b)
	if err != nil {
		return logid.Zero, false
	}
	return id, true
}
