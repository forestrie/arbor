package signer

import (
	"encoding/json"
	"net/http"
)

// EncodeVersion writes a JSON version object to w.
func EncodeVersion(w http.ResponseWriter, version, commit, buildDate string) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]string{
		"version":   version,
		"commit":    commit,
		"buildDate": buildDate,
	})
}
