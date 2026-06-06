package univocity

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/fxamacker/cbor/v2"
)

func (a API) resolveScoped(
	w http.ResponseWriter,
	r *http.Request,
) (ChainReader, common.Address, bool) {
	if a.Pool == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
			"trust-root service unavailable", "RPC pool not configured")
		return nil, common.Address{}, false
	}
	chainStr := r.PathValue("chainId")
	contractStr := r.PathValue("contract")
	chainID, ok := parseChainIDPath(chainStr)
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank",
			"invalid chainId", "expect decimal EIP-155 chain id")
		return nil, common.Address{}, false
	}
	contract, ok := parseContractPath(contractStr)
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank",
			"invalid contract address", "expect 0x-prefixed or 40-char hex")
		return nil, common.Address{}, false
	}
	reader, err := a.Pool.Reader(chainID, contract)
	if err != nil {
		if errors.Is(err, ErrChainNotConfigured) {
			a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
				"chain not configured", err.Error())
			return nil, common.Address{}, false
		}
		a.Logger.Error("rpc reader failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank",
			"rpc connection failed", err.Error())
		return nil, common.Address{}, false
	}
	return reader, contract, true
}

func (a API) resolveForest(
	w http.ResponseWriter,
	r *http.Request,
	logID logid.UUID,
) (ForestEntry, ChainReader, bool) {
	if a.Resolver == nil && a.Store == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
			"forest resolver unavailable", "")
		return ForestEntry{}, nil, false
	}
	// Index (owned store) first, then genesis-identity + on-chain probe resolver.
	entry, reader, err := a.resolveForestForLog(r.Context(), logID)
	if err != nil {
		switch {
		case errors.Is(err, ErrAmbiguousForest):
			a.Logger.Error("ambiguous forest resolution", "logId", logID.String())
			a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
				"ambiguous log forest", err.Error())
		case errors.Is(err, ErrLogNotResolved):
			a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
				"log not resolved", "forest unknown or log not yet on-chain")
		case errors.Is(err, ErrChainNotConfigured):
			a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
				"chain not configured", err.Error())
		default:
			a.Logger.Error("resolve failed", "error", err, "logId", logID.String())
			a.writeProblem(w, r, http.StatusBadGateway, "about:blank",
				"resolve failed", err.Error())
		}
		return ForestEntry{}, nil, false
	}
	return entry, reader, true
}

func (a API) handleScopedRoot(w http.ResponseWriter, r *http.Request) {
	reader, _, ok := a.resolveScoped(w, r)
	if !ok {
		return
	}
	root, err := reader.RootLogId(r.Context())
	if err != nil {
		a.Logger.Error("rootLogId call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
		return
	}
	writeRootJSON(w, root)
}

func (a API) handleScopedLogsList(w http.ResponseWriter, r *http.Request) {
	reader, _, ok := a.resolveScoped(w, r)
	if !ok {
		return
	}
	root, err := reader.RootLogId(r.Context())
	if err != nil {
		a.Logger.Error("rootLogId call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
		return
	}
	var rootStr *string
	authLogs := []string{}
	if !root.IsZero() {
		h := root.String()
		rootStr = &h
		authLogs = append(authLogs, h)
	}
	resp := struct {
		RootLogId *string  `json:"rootLogId"`
		AuthLogs  []string `json:"authLogs"`
	}{
		RootLogId: rootStr,
		AuthLogs:  authLogs,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (a API) handleScopedLogConfig(w http.ResponseWriter, r *http.Request) {
	reader, _, ok := a.resolveScoped(w, r)
	if !ok {
		return
	}
	logId, ok := logIDFromPathValue(r.PathValue("logId"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId",
			"expect canonical UUID")
		return
	}
	a.writeLogConfig(w, r, reader, logId)
}

func (a API) handleScopedPublicRoot(w http.ResponseWriter, r *http.Request) {
	reader, _, ok := a.resolveScoped(w, r)
	if !ok {
		return
	}
	logId, ok := logIDFromPathValue(r.PathValue("logId"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId",
			"expect canonical UUID")
		return
	}
	a.writePublicRoot(w, r, reader, logId, false, ForestEntry{})
}

func (a API) handleLogIDRoot(w http.ResponseWriter, r *http.Request) {
	logId, ok := logIDFromPathValue(r.PathValue("logId"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId",
			"expect canonical UUID")
		return
	}
	entry, _, ok := a.resolveForest(w, r, logId)
	if !ok {
		return
	}
	resp := struct {
		Exists    bool   `json:"exists"`
		RootLogId string `json:"rootLogId"`
	}{
		Exists:    true,
		RootLogId: entry.R.String(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (a API) handleLogIDPublicRoot(w http.ResponseWriter, r *http.Request) {
	logId, ok := logIDFromPathValue(r.PathValue("logId"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId",
			"expect canonical UUID")
		return
	}
	entry, reader, ok := a.resolveForest(w, r, logId)
	if !ok {
		return
	}
	a.writePublicRoot(w, r, reader, logId, true, entry)
}

// authorityResponse is the CBOR authority binding for a logId: the authoritative
// root identity (alg,key) plus the forest root and chain binding. Unlike
// public-root it resolves *cold* logs from the chain-valid stored grant chain.
type authorityResponse struct {
	LogID     []byte `cbor:"logId,omitempty"`
	RootLogID []byte `cbor:"rootLogId,omitempty"`
	Alg       int64  `cbor:"alg,omitempty"`
	Key       []byte `cbor:"key,omitempty"`
	ChainID   string `cbor:"chainId,omitempty"`
	Contract  string `cbor:"contract,omitempty"`
	Source    string `cbor:"source,omitempty"`
}

// handleLogIDAuthority resolves the authoritative root key + chain binding for a
// logId. It is the trusted lookup the sealer uses before signing a checkpoint:
// the sealer verifies the (untrusted) delegation certificate locally against the
// returned key, so this endpoint is a pure, non-mutating resolution (no
// certificate is sent and there is no allow/deny verdict here).
func (a API) handleLogIDAuthority(w http.ResponseWriter, r *http.Request) {
	logID, ok := logIDFromPathValue(r.PathValue("logId"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId",
			"expect canonical UUID")
		return
	}
	res, err := a.resolveAuthority(r.Context(), logID)
	if err != nil {
		a.writeAuthorityError(w, r, err)
		return
	}
	resp := authorityResponse{
		LogID:     res.LogID[:],
		RootLogID: res.RootLogID[:],
		Alg:       res.Alg,
		Key:       res.Key,
		ChainID:   strconv.FormatUint(res.ChainID, 10),
		Contract:  res.Contract.Hex(),
		Source:    res.Source,
	}
	out, err := cbor.Marshal(resp)
	if err != nil {
		a.writeProblem(w, r, http.StatusInternalServerError, "about:blank",
			"encode failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func (a API) writeAuthorityError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrLogNotResolved), errors.Is(err, ErrAmbiguousForest):
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
			"log not resolved", err.Error())
	default:
		a.Logger.Info("authority resolution failed", "logId", logID(r).String(), "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank",
			"authority resolution failed", err.Error())
	}
}

// logID extracts the path logId for logging (best effort; empty on parse fail).
func logID(r *http.Request) logid.UUID {
	id, _ := logIDFromPathValue(r.PathValue("logId"))
	return id
}

func writeRootJSON(w http.ResponseWriter, root logid.UUID) {
	exists := !root.IsZero()
	resp := struct {
		Exists    bool   `json:"exists"`
		RootLogId string `json:"rootLogId"`
	}{
		Exists:    exists,
		RootLogId: root.String(),
	}
	if !exists {
		resp.RootLogId = ""
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (a API) writeLogConfig(
	w http.ResponseWriter,
	r *http.Request,
	reader ChainReader,
	logId logid.UUID,
) {
	initialized, err := reader.IsLogInitialized(r.Context(), logId)
	if err != nil {
		a.Logger.Error("isLogInitialized call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
		return
	}
	if !initialized {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "log not found", "log not initialized")
		return
	}
	cfg, err := reader.LogConfig(r.Context(), logId)
	if err != nil {
		a.Logger.Error("logConfig call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
		return
	}
	resp := struct {
		Kind          string `json:"kind"`
		AuthLogId     string `json:"authLogId"`
		InitializedAt uint64 `json:"initializedAt"`
	}{
		Kind:          cfg.Kind.String(),
		AuthLogId:     cfg.AuthLogId.String(),
		InitializedAt: cfg.InitializedAt,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (a API) writePublicRoot(
	w http.ResponseWriter,
	r *http.Request,
	reader ChainReader,
	logId logid.UUID,
	includeChainBinding bool,
	entry ForestEntry,
) {
	initialized, err := reader.IsLogInitialized(r.Context(), logId)
	if err != nil {
		a.Logger.Error("isLogInitialized call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
		return
	}
	if !initialized {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "log not found", "log not initialized")
		return
	}
	cfg, err := reader.LogConfig(r.Context(), logId)
	if err != nil {
		a.Logger.Error("logConfig call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
		return
	}
	alg, key, ok := grantDataIdentity(cfg.RootKey)
	if !ok {
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed",
			fmt.Sprintf("invalid on-chain rootKey length %d", len(cfg.RootKey)))
		return
	}
	if includeChainBinding || strings.Contains(r.Header.Get("Accept"), "application/cbor") {
		record := TrustRootResponse{
			LogID: logId[:],
			Alg:   alg,
			Key:   key,
		}
		if includeChainBinding && !entry.R.IsZero() {
			record.ChainID = strconv.FormatUint(entry.ChainID, 10)
			record.ContractAddress = entry.Contract.Hex()
		}
		body, err := cbor.Marshal(record)
		if err != nil {
			a.writeProblem(w, r, http.StatusInternalServerError, "about:blank",
				"encode failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}
	x, y := es256XYFromOpaqueKey(alg, key)
	resp := struct {
		LogId      string `json:"logId"`
		Kind       string `json:"kind"`
		OwnerLogId string `json:"ownerLogId"`
		RootKeyX   string `json:"rootKeyX,omitempty"`
		RootKeyY   string `json:"rootKeyY,omitempty"`
		RootKey    string `json:"rootKey,omitempty"`
		Alg        int64  `json:"alg"`
	}{
		LogId:      logId.String(),
		Kind:       cfg.Kind.String(),
		OwnerLogId: cfg.AuthLogId.String(),
		Alg:        alg,
	}
	if alg == coseAlgES256 {
		resp.RootKeyX = bytes32Hex(x)
		resp.RootKeyY = bytes32Hex(y)
	} else {
		resp.RootKey = "0x" + hex.EncodeToString(key)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func bytes32Hex(b [32]byte) string {
	return "0x" + hex.EncodeToString(b[:])
}

func es256XYFromOpaqueKey(alg int64, key []byte) (x, y [32]byte) {
	if alg != coseAlgES256 {
		return [32]byte{}, [32]byte{}
	}
	x, y, _ = grantDataToXY(key)
	return x, y
}
