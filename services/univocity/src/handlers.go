package univocity

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
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
	logID [32]byte,
) (ForestEntry, ChainReader, bool) {
	if a.Resolver == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
			"forest resolver unavailable", "")
		return ForestEntry{}, nil, false
	}
	entry, err := a.Resolver.Resolve(r.Context(), logID)
	if err != nil {
		if errors.Is(err, ErrAmbiguousForest) {
			a.Logger.Error("ambiguous forest resolution", "logId", LogIDToHex(logID))
			a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
				"ambiguous log forest", err.Error())
			return ForestEntry{}, nil, false
		}
		if errors.Is(err, ErrLogNotResolved) {
			a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
				"log not resolved", "forest unknown or log not yet on-chain")
			return ForestEntry{}, nil, false
		}
		a.Logger.Error("resolve failed", "error", err, "logId", LogIDToHex(logID))
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank",
			"resolve failed", err.Error())
		return ForestEntry{}, nil, false
	}
	reader, err := a.Pool.Reader(entry.ChainID, entry.Contract)
	if err != nil {
		if errors.Is(err, ErrChainNotConfigured) {
			a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank",
				"chain not configured", err.Error())
			return ForestEntry{}, nil, false
		}
		a.Logger.Error("rpc reader failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank",
			"rpc connection failed", err.Error())
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
	if root != [32]byte{} {
		h := LogIDToHex(root)
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
			"expect 0x-prefixed hex (32 or 64 chars)")
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
			"expect 0x-prefixed hex (32 or 64 chars)")
		return
	}
	a.writePublicRoot(w, r, reader, logId, false, ForestEntry{})
}

func (a API) handleLogIDRoot(w http.ResponseWriter, r *http.Request) {
	logId, ok := logIDFromPathValue(r.PathValue("logId"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId",
			"expect 0x-prefixed hex (32 or 64 chars)")
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
		RootLogId: LogIDToHex(entry.R),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (a API) handleLogIDPublicRoot(w http.ResponseWriter, r *http.Request) {
	logId, ok := logIDFromPathValue(r.PathValue("logId"))
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId",
			"expect 0x-prefixed hex (32 or 64 chars)")
		return
	}
	entry, reader, ok := a.resolveForest(w, r, logId)
	if !ok {
		return
	}
	a.writePublicRoot(w, r, reader, logId, true, entry)
}

func writeRootJSON(w http.ResponseWriter, root [32]byte) {
	exists := root != [32]byte{}
	resp := struct {
		Exists    bool   `json:"exists"`
		RootLogId string `json:"rootLogId"`
	}{
		Exists:    exists,
		RootLogId: LogIDToHex(root),
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
	logId [32]byte,
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
		AuthLogId:     LogIDToHex(cfg.AuthLogId),
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
	logId [32]byte,
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
	if len(cfg.RootKey) == 20 {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "log not found",
			"KS256 trust root not supported via univocity")
		return
	}
	rootKeyX, rootKeyY, err := reader.LogRootKey(r.Context(), logId)
	if err != nil {
		a.Logger.Error("logRootKey call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
		return
	}
	if includeChainBinding || strings.Contains(r.Header.Get("Accept"), "application/cbor") {
		record := TrustRootResponse{
			LogID: logId[:],
			Alg:   "ES256",
			X:     rootKeyX[:],
			Y:     rootKeyY[:],
		}
		if includeChainBinding && entry.R != [32]byte{} {
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
	resp := struct {
		LogId      string `json:"logId"`
		Kind       string `json:"kind"`
		OwnerLogId string `json:"ownerLogId"`
		RootKeyX   string `json:"rootKeyX"`
		RootKeyY   string `json:"rootKeyY"`
	}{
		LogId:      LogIDToHex(logId),
		Kind:       cfg.Kind.String(),
		OwnerLogId: LogIDToHex(cfg.AuthLogId),
		RootKeyX:   LogIDToHex(rootKeyX),
		RootKeyY:   LogIDToHex(rootKeyY),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
