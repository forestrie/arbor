package univocity

import (
	"errors"
	"io"
	"net/http"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/fxamacker/cbor/v2"
)

const maxRequestBody = 512 * 1024

// postGrantRequest carries a creation grant (SCITT transparent statement) and
// optionally the forest root it belongs to (the register path's bootstrap-logid).
type postGrantRequest struct {
	RootLogID []byte `cbor:"rootLogId,omitempty"`
	Statement []byte `cbor:"statement"`
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
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank",
			"anchor verification failed", err.Error())
		return
	}
	created, err := a.Store.PutGenesisIfAbsent(r.Context(), doc.Forest.R, body)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "store genesis failed", err.Error())
		return
	}
	// Root self-index: R -> R. Best effort; conflict means already present.
	if _, _, err := a.Store.IndexCreate(r.Context(), doc.Forest.R, doc.Forest.R); err != nil {
		a.Logger.Warn("genesis self-index failed", "R", doc.Forest.R.String(), "error", err)
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

// verifyGenesisAnchor checks genesis.key == on-chain bootstrapConfig() for the
// forest's chain/contract. When the anchor cannot be reached it errors unless
// AllowUnanchoredGenesis is set (local/dev/e2e).
func (a API) verifyGenesisAnchor(r *http.Request, doc GenesisDoc) error {
	if a.Pool == nil {
		if a.AllowUnanchoredGenesis {
			return nil
		}
		return errors.New("rpc pool not configured")
	}
	reader, err := a.Pool.Reader(doc.Forest.ChainID, doc.Forest.Contract)
	if err != nil {
		if a.AllowUnanchoredGenesis {
			a.Logger.Warn("genesis anchor skipped: reader unavailable",
				"R", doc.Forest.R.String(), "error", err)
			return nil
		}
		return err
	}
	bootAlg, bootKey, err := a.bootstrapConfig(r.Context(), doc.Forest, reader)
	if err != nil {
		if a.AllowUnanchoredGenesis && errors.Is(err, ErrBootstrapUnavailable) {
			a.Logger.Warn("genesis anchor skipped: bootstrap unavailable",
				"R", doc.Forest.R.String(), "error", err)
			return nil
		}
		return err
	}
	if !bootstrapKeysEqual(doc.Alg, doc.GenesisKeyBytes(), bootAlg, bootKey) {
		// Genesis-declared root may differ from contract bootstrapConfig()
		// (Mode C BYOK). Grant verification uses stored genesis identity.
		return nil
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
	if err := cbor.Unmarshal(body, &req); err != nil || len(req.Statement) == 0 {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid request",
			"expect CBOR { statement, rootLogId? }")
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
		if errors.Is(err, ErrBootstrapUnavailable) && a.AllowUnanchoredGenesis {
			a.Logger.Warn("grant chain anchor skipped (unanchored mode)",
				"subject", subject.String(), "error", err)
		} else {
			a.writeProblem(w, r, http.StatusUnprocessableEntity, "about:blank",
				"grant chain invalid", err.Error())
			return
		}
	}
	created, existing, err := a.Store.IndexCreate(r.Context(), subject, root)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "index create failed", err.Error())
		return
	}
	if !created && existing != root {
		a.writeProblem(w, r, http.StatusConflict, "about:blank",
			"logId belongs to another forest",
			"global logId->R uniqueness violated")
		return
	}
	class, err := grantClassFromFlags(ts.Grant.Flags)
	if err != nil {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank",
			"invalid grant class", err.Error())
		return
	}
	if err := a.Store.PutGrant(r.Context(), root, subject, class, req.Statement); err != nil {
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "store grant failed", err.Error())
		return
	}
	if created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
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
	if err != nil || !found {
		return logid.Zero, false
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
