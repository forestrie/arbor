package univocity

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (a API) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if a.Chain == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank", "auth-log service unavailable", "UNIVOCITY_RPC_URL and UNIVOCITY_CONTRACT_ADDRESS not configured")
		return
	}
	root, err := a.Chain.RootLogId(r.Context())
	if err != nil {
		a.Logger.Error("rootLogId call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
		return
	}
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

func (a API) handleLogsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if a.Chain == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank", "auth-log service unavailable", "UNIVOCITY_RPC_URL and UNIVOCITY_CONTRACT_ADDRESS not configured")
		return
	}
	root, err := a.Chain.RootLogId(r.Context())
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
		RootLogId *string  `json:"rootLogId,omitempty"`
		AuthLogs  []string `json:"authLogs"`
	}{
		RootLogId: rootStr,
		AuthLogs:  authLogs,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (a API) handleLogConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if a.Chain == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank", "auth-log service unavailable", "")
		return
	}
	logId, ok := logIDFromPath(r.URL.Path, "/config")
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId", "expect 0x-prefixed hex (32 or 64 chars)")
		return
	}
	initialized, err := a.Chain.IsLogInitialized(r.Context(), logId)
	if err != nil {
		a.Logger.Error("isLogInitialized call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
		return
	}
	if !initialized {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "log not found", "log not initialized")
		return
	}
	cfg, err := a.Chain.LogConfig(r.Context(), logId)
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

func (a API) handleSigningKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeProblem(w, r, http.StatusMethodNotAllowed, "about:blank", "method not allowed", "")
		return
	}
	if a.Chain == nil {
		a.writeProblem(w, r, http.StatusServiceUnavailable, "about:blank", "auth-log service unavailable", "")
		return
	}
	logId, ok := logIDFromPath(r.URL.Path, "/signing-key")
	if !ok {
		a.writeProblem(w, r, http.StatusBadRequest, "about:blank", "invalid logId", "expect 0x-prefixed hex (32 or 64 chars)")
		return
	}
	initialized, err := a.Chain.IsLogInitialized(r.Context(), logId)
	if err != nil {
		a.Logger.Error("isLogInitialized call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
		return
	}
	if !initialized {
		a.writeProblem(w, r, http.StatusNotFound, "about:blank", "log not found", "log not initialized")
		return
	}
	cfg, err := a.Chain.LogConfig(r.Context(), logId)
	if err != nil {
		a.Logger.Error("logConfig call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
		return
	}
	rootKeyX, rootKeyY, err := a.Chain.LogRootKey(r.Context(), logId)
	if err != nil {
		a.Logger.Error("logRootKey call failed", "error", err)
		a.writeProblem(w, r, http.StatusBadGateway, "about:blank", "contract call failed", err.Error())
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

func logIDFromPath(path, suffix string) ([32]byte, bool) {
	const prefix = "/api/logs/"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return [32]byte{}, false
	}
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.TrimSuffix(rest, suffix)
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return [32]byte{}, false
	}
	return LogIDFromHex(rest)
}
